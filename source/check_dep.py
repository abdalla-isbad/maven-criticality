import os, time
from concurrent.futures import ThreadPoolExecutor, as_completed
import pandas as pd
import pyarrow as pa, pyarrow.parquet as pq
from neo4j import GraphDatabase
from tqdm import tqdm

# ─────── CONFIG ──────────────────────────────────────────────
NEO4J_URI        = "bolt://localhost:7687"
NEO4J_USER       = "neo4j"
NEO4J_PASSWORD   = "password"
TOP_CSV          = "top_artifact_starts.csv"       # artifact_id,gav,node_id
OUT_PARQUET      = "reverse_union_dependents.parquet"
ERROR_LOG        = "reverse_failed_artifacts.txt"
EXPORT_LOG       = "reverse_export_log.txt"

MAX_WORKERS      = 3
BATCH_SIZE       = 100
FLUSH_EVERY_SECS = 30
# ─────────────────────────────────────────────────────────────

SCHEMA = pa.schema([
    ('artifact_id',  pa.string()),
    ('depth1_cnt',   pa.int32()),
    ('depth2_cnt',   pa.int32()),
    ('depth3_cnt',   pa.int32()),
    ('depth1_pct',   pa.float32()),
    ('depth2_pct',   pa.float32()),
    ('depth3_pct',   pa.float32()),
])

def log(msg: str):
    tqdm.write(msg)
    with open(EXPORT_LOG, "a") as f:
        f.write(msg + "\n")

def load_artifacts(csv_path: str) -> list[str]:
    df = pd.read_csv(csv_path, usecols=['artifact_id'])
    return df['artifact_id'].drop_duplicates().tolist()

def get_total_release_count(driver) -> int:
    query = """
    MATCH (r:Release)-[d:DEPENDS_ON]->()
    WHERE d.resolution_route = 'DirectMatch'
    RETURN count(DISTINCT r) AS total
    """
    result = driver.execute_query(query, database_=None, result_transformer_=lambda r: r.single())
    return result["total"] if result else 0

def neo_worker(aid: str, driver, total_releases: int) -> dict | None:
    log(f"⏳ {aid}: starting")
    counts, times = {}, {}

    try:
        for depth in [1, 2, 3]:
            t0 = time.time()
            query = f"""
            MATCH path = (r:Release)-[deps:DEPENDS_ON*1..{depth}]->(target:Release)<-[:PUBLISHES]-(a:Artifact {{artifact_id: $aid}})
            WHERE ALL(edge IN deps WHERE edge.resolution_route = 'DirectMatch')
            RETURN count(DISTINCT r) AS c
            """
            res = driver.execute_query(query, aid=aid, database_=None, result_transformer_=lambda r: r.single())
            counts[f"depth{depth}_cnt"] = res['c'] if res else 0
            times[f"depth{depth}"] = time.time() - t0

        if total_releases == 0:
            raise ValueError("No total releases found (division by zero)")

        row = {
            'artifact_id': aid,
            'depth1_cnt': counts['depth1_cnt'],
            'depth2_cnt': counts['depth2_cnt'],
            'depth3_cnt': counts['depth3_cnt'],
            'depth1_pct': counts['depth1_cnt'] / total_releases,
            'depth2_pct': counts['depth2_cnt'] / total_releases,
            'depth3_pct': counts['depth3_cnt'] / total_releases,
        }

        log(f"{aid}: d1={counts['depth1_cnt']} ({times['depth1']:.1f}s), "
            f"d2={counts['depth2_cnt']} ({times['depth2']:.1f}s), "
            f"d3={counts['depth3_cnt']} ({times['depth3']:.1f}s) → total={sum(times.values()):.1f}s")

        return row

    except Exception as e:
        log(f"{aid}: {e}")
        with open(ERROR_LOG, "a") as f:
            f.write(f"{aid}\n")
        return None

def flush_batch(batch, writer):
    if not batch:
        return
    table = pa.Table.from_pylist(batch, schema=SCHEMA)
    writer.write_table(table)
    batch.clear()

def main():
    if os.path.exists(EXPORT_LOG):
        os.remove(EXPORT_LOG)

    todo = load_artifacts(TOP_CSV)
    done = set()

    if os.path.exists(OUT_PARQUET):
        try:
            existing = pq.read_table(OUT_PARQUET, columns=['artifact_id']).to_pandas()
            done.update(existing['artifact_id'].tolist())
        except Exception as e:
            print("Failed to read existing output file:", e)
            return

    pending = [aid for aid in todo if aid not in done]
    log(f"▶Remaining artifacts: {len(pending)} (skipped {len(done)})")

    driver = GraphDatabase.driver(
        NEO4J_URI,
        auth=(NEO4J_USER, NEO4J_PASSWORD),
        max_connection_pool_size=MAX_WORKERS * 2,
        connection_acquisition_timeout=600
    )

    writer = pq.ParquetWriter(OUT_PARQUET, SCHEMA, compression='ZSTD', use_dictionary=True)
    batch, last_flush = [], time.time()

    try:
        with driver:
            total_releases = get_total_release_count(driver)
            if total_releases == 0:
                log("No matching releases with resolution_route='DirectMatch'")
                total_releases = 1  # prevent crash
            print(f"Total DirectMatch releases: {total_releases:,}")

            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool, tqdm(
                total=len(pending), desc="Artifacts exported", unit="artifact"
            ) as pbar:
                futures = {pool.submit(neo_worker, aid, driver, total_releases): aid for aid in pending}

                for fut in as_completed(futures):
                    row = fut.result()
                    if row:
                        batch.append(row)

                    if len(batch) >= BATCH_SIZE or (time.time() - last_flush) > FLUSH_EVERY_SECS:
                        flush_batch(batch, writer)
                        last_flush = time.time()

                    pbar.update(1)

    except Exception as e:
        log(f"Unexpected error: {e}")
    finally:
        flush_batch(batch, writer)
        writer.close()
        driver.close()

    print(f"✓ Completed export → {OUT_PARQUET}")

if __name__ == "__main__":
    main()

