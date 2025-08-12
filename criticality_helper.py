# ==============================================================================
# IMPORTS 
# ==============================================================================
import time
import warnings
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional, Tuple, Union, Any
import numpy as np
import pandas as pd
from numba import njit
import matplotlib.pyplot as plt
import seaborn as sns
from IPython.display import display, HTML
import re
from scipy import stats
from sklearn.preprocessing import QuantileTransformer, MinMaxScaler
from scipy.stats import spearmanr
from kmodes.kmodes import KModes
import requests
from tqdm import tqdm
warnings.filterwarnings('ignore')

# ==============================================================================
# CONSTANTS 
# ==============================================================================
SNAPSHOT = "2024-09-04"
MS_PER_DAY = 86_400_000
BYTES_PER_MB = 1_048_576 
TOTAL_RELEASES = 13_002_239
CONNECTED_RELEASES = 12_775_608 
TOTAL_ARTIFACTS = 568_692
CONNECTED_ARTIFACTS = 658_078
RECENT_CVE_YEAR = 2023
PARQUET_PATH = "source/parquet/maven_data.parquet"
ZENODO_DATA_URL = "https://zenodo.org/records/16811178/files/maven_data.parquet?download=1"
REVERSE_DEPS_PATH = "source/parquet/reverse_union_dependents.parquet"
ARTIFACT_DEPENDENTS_PATH = "source/csv/artifact_cumulative_dependents.csv"
CVE_DATA_PATH = "source/parquet/cve_data_filtered.parquet"
CVE_CACHE_PATH = "source/parquet/cve_data_processed.parquet"
TF_PATH = "source/csv/tf_crit.csv"

# ==============================================================================
# NUMBA-ACCELERATED FUNCTIONS 
# ==============================================================================


@njit
def compute_local_max_tau_core_sorted(
    rd_sorted: np.ndarray, 
    missed_sorted: np.ndarray, 
    code_sorted: np.ndarray, 
    sorted_idx: np.ndarray, 
    tau_days: int
) -> np.ndarray:

    n = len(rd_sorted)
    result = np.empty(n, dtype=np.float32)

    # Sliding window over sorted artifact groups: 
    # 1. Iterate over each artifact group
    # 2. For each artifact group, iterate over each artifact in the group
    # 3. For each artifact, calculate the maximum missed value within a tau window (2 years in this case)
    # 4. Store the maximum missed value for the artifact
    # 5. Return the maximum missed value for each artifact
    i = 0
    while i < n:
        curr_code = code_sorted[i]
        j = i
        while j < n and code_sorted[j] == curr_code:
            j += 1

        for k in range(i, j):
            center_day = rd_sorted[k]
            window_min = center_day - tau_days
            window_max = center_day + tau_days
            max_missed = np.float32(1.0)

            for m in range(i, j):
                d = rd_sorted[m]
                if d < window_min:
                    continue
                if d > window_max:
                    break
                max_missed = max(max_missed, missed_sorted[m])

            result[k] = max_missed
        i = j

    # Reorder back to original order
    reordered = np.empty(n, dtype=np.float32)
    for i in range(n):
        reordered[sorted_idx[i]] = result[i]

    return reordered

def compute_local_max_tau(
    release_days: np.ndarray, 
    missed: np.ndarray, 
    artifact_codes: np.ndarray, 
    tau_days: int
) -> np.ndarray:

    sorted_idx = np.lexsort((release_days, artifact_codes))
    rd_sorted = release_days[sorted_idx]
    missed_sorted = missed[sorted_idx]
    code_sorted = artifact_codes[sorted_idx]

    return compute_local_max_tau_core_sorted(
        rd_sorted, missed_sorted, code_sorted, sorted_idx, tau_days
    )


# ==============================================================================
# CRITICALITY HELPER CLASS
# ==============================================================================

class CriticalityHelper:
 

    def __init__(
        self, 
        parquet_path: Union[str, Path] = PARQUET_PATH,
        style: str = 'seaborn-v0_8'
    ):

        self.parquet_path = Path(parquet_path)
        self.df: Optional[pd.DataFrame] = None
        self.df_artifacts = pd.DataFrame(columns=['artifact_id', 'truck_factor', 'criticality_score_pf', 'mean_pagerank'])
        self.weights: Optional[Dict[str, float]] = None
        self.processing_stats: Dict[str, Any] = {}
        self.tf_data: Optional[pd.DataFrame] = None
        self.reverse_deps_data: Optional[pd.DataFrame] = None
        self._artifact_metrics: Dict[str, Dict[str, Any]] = {}
        
        try:
            plt.style.use(style)
        except OSError:
            plt.style.use('default')
        sns.set_palette("husl")
    
    # ========================================================================
    # 1. DATA LOADING AND PREPROCESSING
    # ========================================================================
    def _download_data_if_missing(self, verbose: bool = True) -> None:
        data_path = Path(self.parquet_path)
        
        if data_path.exists():
            return
            
        if verbose:
            print("Main dataset not found locally. Downloading from Zenodo...")
            
        
        # Create directory if needed
        data_path.parent.mkdir(parents=True, exist_ok=True)
        
        try:
            response = requests.get(ZENODO_DATA_URL, stream=True)
            response.raise_for_status()
            
            total_size = int(response.headers.get('content-length', 0))
            
            with open(data_path, 'wb') as f:
                if verbose and total_size > 0:
                    with tqdm(total=total_size, unit='B', unit_scale=True, desc="Downloading") as pbar:
                        for chunk in response.iter_content(chunk_size=8192):
                            f.write(chunk)
                            pbar.update(len(chunk))
                else:
                    for chunk in response.iter_content(chunk_size=8192):
                        f.write(chunk)
            
            if verbose:
                print(f"Download complete: {data_path}")
                print(f"File size: {data_path.stat().st_size / (1024**3):.2f} GB")
                
        except Exception as e:
            if data_path.exists():
                data_path.unlink()  # Remove partial file
            raise ValueError(f"Failed to download data from Zenodo: {e}")

    def load_and_preprocess_data(
        self,
        verbose: bool = True,
        snapshot: Union[str, pd.Timestamp, None] = SNAPSHOT,
    ) -> pd.DataFrame:
        if verbose:
            print("Loading Maven Central release data...")

        # Download data if missing
        self._download_data_if_missing(verbose)

        try:
            self.df = pd.read_parquet(self.parquet_path)
            cols_to_drop = ['dep_d1', 'dep_d2', 'dep_d3', 'version', 'tds_size']
            self.df = self.df.drop(columns=[col for col in cols_to_drop if col in self.df.columns])
        except Exception as e:
            raise ValueError(f"Failed to load parquet file: {e}")

        cve_cache_path = CVE_CACHE_PATH
        try:
            if Path(cve_cache_path).exists():
                if verbose:
                    print("Loading cached processed CVE data...")
                cve_processed = pd.read_parquet(cve_cache_path)
                
                if self.df['gav'].dtype.name != 'category':
                    self.df['gav'] = self.df['gav'].astype('category')
                if cve_processed['gav'].dtype.name != 'category':
                    cve_processed['gav'] = cve_processed['gav'].astype('category')
                
                self.df = self.df.merge(cve_processed, on='gav', how='left')
                if verbose:
                    print("Cached CVE data merged")
            else:
                if verbose:
                    print("Processing CVE data (first time - will cache for future use)...")
                cve_data = pd.read_parquet(CVE_DATA_PATH)
                
                cve_data['cve_severities'] = cve_data['cve_severities'].fillna('')
                
                severities = ['CRITICAL', 'HIGH', 'MODERATE', 'LOW']
                cve_array = np.asarray(cve_data['cve_severities'].values, dtype='U500')
                
                for severity in severities:
                    counts = np.char.count(cve_array, severity).astype(np.int16)
                    cve_data[f'cve_{severity.lower()}_count'] = counts
                
                merge_cols = ['gav', 'has_cve', 'cve_count', 'cve_names', 'cve_severities', 'max_severity'] + [f'cve_{sev.lower()}_count' for sev in severities]
                cve_processed = cve_data[merge_cols].copy()
                
                cve_processed.to_parquet(cve_cache_path, compression='snappy')
                
                self.df = self.df.merge(cve_processed, on='gav', how='left')
                
                if verbose:
                    print("CVE data processed, cached, and merged")
        except Exception as e:
            if verbose:
                print(f"Warning: Could not load or merge CVE data - {e}")
                
            self.df['has_cve'] = False
            self.df['cve_count'] = 0
            self.df['cve_names'] = ''
            self.df['max_severity'] = 'NONE'
            self.df['cve_severities'] = ''
            severities = ['CRITICAL', 'HIGH', 'MODERATE', 'LOW']
            for severity in severities:
                self.df[f'cve_{severity.lower()}_count'] = 0

        self.df['has_cve'] = self.df['has_cve'].fillna(False)
        self.df['cve_count'] = self.df['cve_count'].fillna(0).astype(int)
        self.df['max_severity'] = self.df['max_severity'].fillna('NONE')
        self.df['cve_severities'] = self.df['cve_severities'].fillna('')
        def extract_cve_years(cve_string: str) -> list:
            if not isinstance(cve_string, str) or not cve_string.startswith("CVE-"):
                return []
            return [int(y) for y in re.findall(r'CVE-(\d{4})-\d+', cve_string)]

        self.df['cve_names'] = self.df['cve_names'].fillna('')
        self.df["cve_years"] = self.df["cve_names"].apply(extract_cve_years)

        self.df["has_recent_cve"] = self.df["cve_years"].apply(
            lambda years: any(y >= RECENT_CVE_YEAR for y in years)
        )

        
        self.df["recent_cve_count"] = self.df["cve_years"].apply(
            lambda years: sum(1 for y in years if y >= RECENT_CVE_YEAR)
        )       
        
        severities = ['CRITICAL', 'HIGH', 'MODERATE', 'LOW']
        for severity in severities:
            col_name = f'cve_{severity.lower()}_count'
            if col_name not in self.df.columns:
                self.df[col_name] = 0
            else:
                self.df[col_name] = self.df[col_name].fillna(0).astype(np.int16)

        
        self.df['release_timestamp'] = pd.to_datetime(self.df['timestamp'], unit='ms', utc=True)
        snap_ts = pd.Timestamp(snapshot, tz='UTC')
        recomputed = (snap_ts - self.df['release_timestamp']).dt.total_seconds() * 1000
        needs_patch = (self.df['ageMs'] <= 0) | (self.df['ageMs'].isna())
        self.df['ageMs'] = np.where(needs_patch, recomputed, self.df['ageMs'])
        self.df['release_days'] = self.df['ageMs'] / MS_PER_DAY

        agg_dict = {
            'pagerank': 'mean',
            'tds_core': 'mean',
            'is_bundle': 'any',
            'release_timestamp': ['count', 'max'],
            'has_cve': 'any',
            'cve_count': 'sum',
            'has_recent_cve': 'any',
            'recent_cve_count': 'sum',
            'max_severity': lambda x: x.value_counts().index[0] if not x.value_counts().empty else 'NONE'
        }
        for severity in severities:
            agg_dict[f'cve_{severity.lower()}_count'] = 'sum'

        artifact_metrics = (
            self.df.groupby('artifact_id')
            .agg(agg_dict)
            .reset_index()
        )
        artifact_metrics.columns = [
            '_'.join(col).strip('_') if isinstance(col, tuple) else col
            for col in artifact_metrics.columns
        ]
        artifact_metrics = artifact_metrics.rename(columns={
            'pagerank_mean': 'mean_pagerank',
            'tds_core_mean': 'mean_tds',
            'release_timestamp_count': 'num_releases',
            'release_timestamp_max': 'latest_release',
            'is_bundle_any': 'is_bundle',
            'has_cve_any': 'has_cve',
            'cve_count_sum': 'total_cve_count',
            'has_recent_cve_any': 'has_recent_cve',
            'recent_cve_count_sum': 'total_recent_cve_count',
            'max_severity_<lambda>': 'predominant_max_severity'
        })
        artifact_metrics = artifact_metrics.sort_values('mean_pagerank', ascending=False)
        self.df_artifacts = artifact_metrics.copy()

        try:
            reverse_deps_path = Path(REVERSE_DEPS_PATH)
            if reverse_deps_path.exists():
                reverse_deps_data = pd.read_parquet(reverse_deps_path)
                self.df_artifacts = self.df_artifacts.merge(
                    reverse_deps_data[['artifact_id', 'depth1_cnt', 'depth2_cnt', 'depth3_cnt']],
                    on='artifact_id',
                    how='left'
                )
                if verbose:
                    print(f"Dependency data merged into artifact-level DataFrame")
            else:
                if verbose:
                    print(f"Reverse dependency data file not found at {reverse_deps_path}")
        except Exception as e:
            if verbose:
                print(f"Warning: Could not load reverse dependency data - {e}")

        self._load_auxiliary_data(verbose)

        if self.tf_data is not None:
            self.df_artifacts['artifact_id'] = self.df_artifacts['artifact_id'].str.strip().str.lower()
            self.tf_data['artifact_id'] = self.tf_data['artifact_id'].str.strip().str.lower()
            self.df_artifacts = self.df_artifacts.merge(
                self.tf_data[['artifact_id', 'truck_factor', 'criticality_score_pf']],
                on='artifact_id',
                how='left'
            )
            if verbose:
                print(f"Auxiliary data merged into artifact-level DataFrame")


        required_cols = ['artifact_id', 'mean_pagerank', 'truck_factor', 'criticality_score_pf']
        missing_cols = [col for col in required_cols if col not in self.df_artifacts.columns]
        if missing_cols:
            raise ValueError(f"Missing required columns in df_artifacts: {missing_cols}")

        return self.df
    
    def _format_dependency_counts(
        self,
        counts: pd.Series,
        total_releases: int,
        connected_releases: int
    ) -> str:

        count = counts
        abs_pct = (count / total_releases) * 100
        rel_pct = (count / connected_releases) * 100
        return f"{count:,} ({abs_pct:.1f}% / {rel_pct:.1f}%)"

    def _load_auxiliary_data(self, verbose: bool = True) -> None:
        if verbose:
            print("Loading auxiliary data for Pfeiffer's work replication...")

        try:
            tf_path = Path(TF_PATH)
            if tf_path.exists():
                tf_data = pd.read_csv(tf_path)
                tf_data.rename(
                    columns={
                        'truckFactor': 'truck_factor',
                        'criticality_score': 'criticality_score_pf'
                    },
                    inplace=True
                )
                tf_data['artifact_id'] = tf_data['artifact_id'].str.strip().str.lower()

                tf_data = tf_data[tf_data['criticality_score_pf'] != -1]

                if self.df_artifacts is not None and not self.df_artifacts.empty:
                    self.df_artifacts['artifact_id'] = self.df_artifacts['artifact_id'].str.strip().str.lower()
                    self.df_artifacts = self.df_artifacts.merge(
                        tf_data[['artifact_id', 'truck_factor', 'criticality_score_pf']],
                        on='artifact_id',
                        how='left'
                    )
                    if verbose:
                        print(f"TF data merged into artifact-level DataFrame")
                else:
                    if verbose:
                        print("df_artifacts is empty. Ensure artifact-level data is populated before merging.")
            else:
                if verbose:
                    print(f"TF data file not found at {tf_path}")
        except Exception as e:
            if verbose:
                print(f"Warning: Could not load TF data - {e}")

    def get_dataset_overview(self) -> Dict[str, Any]:

        if self.df is None:
            raise ValueError("Data not loaded. Run load_and_preprocess_data() first.")
        
        overview = {
            'total_releases': len(self.df),
            'unique_artifacts': self.df['artifact_id'].nunique(),
            'date_range': {
                'earliest': self.df['release_timestamp'].min(),
                'latest': self.df['release_timestamp'].max()
            },
            'bundle_stats': {
                'count': self.df['is_bundle'].sum(),
                'percentage': self.df['is_bundle'].mean() * 100
            },
            'tds_stats': {
                'mean': self.df['tds_core'].mean(),
                'median': self.df['tds_core'].median(),
                'max': self.df['tds_core'].max(),
                'zero_count': (self.df['tds_core'] == 0).sum()
            },
            'memory_usage_mb': self.df.memory_usage(deep=True).sum() / BYTES_PER_MB
        }
        
        return overview
    
    # ========================================================================
    # 2. SCORE PROCESSING FUNCTIONS
    # ========================================================================
    
    def _log_minmax(self, series: pd.Series, cap_pct: float = 99.95) -> Tuple[pd.Series, float]:

        cap = np.percentile(series, cap_pct)
        series_capped = np.minimum(series, cap)
        log_vals = np.log1p(series_capped)

        log_min = log_vals.min()
        log_max = log_vals.max()
        norm = (log_vals - log_min) / (log_max - log_min)

        return norm, cap

    def process_tds_scores(
        self,
        cap_pct: float = 99.9,
        bundle_penalty: float = 0.5,
        use_recent: bool = False,
        store_both_versions: bool = False,
    ) -> pd.Series:

        if self.df_artifacts is None or "mean_tds" not in self.df_artifacts.columns:
            raise ValueError("Artifact-level data not loaded or missing 'mean_tds' column.")

        tds_raw = self.df_artifacts["mean_tds"].astype(float).copy()

        if use_recent:
            if not {"recent_dependencies", "direct_deps"}.issubset(self.df_artifacts.columns):
                raise ValueError("Recent/dependency columns not found in artifact-level data.")
            w = (self.df_artifacts["recent_dependencies"] + 1) / (self.df_artifacts["direct_deps"] + 1)
            tds_raw *= w.clip(upper=5)

        if "is_bundle" in self.df_artifacts.columns:
            tds_raw[self.df_artifacts["is_bundle"]] *= bundle_penalty

        self.df_artifacts["tds_score"], cap_val = self._log_minmax(tds_raw, cap_pct)

        self.processing_stats.update({
            "tds_cap_pct": cap_pct,
            "tds_cap_value": cap_val,
            "tds_bundle_penalty": bundle_penalty,
            "tds_use_recent": use_recent,
            "tds_transform": "cap → log1p → minmax (artifact-level)"
        })

        print(f"Artifact-level TDS processed (cap {cap_pct:.2f}%, {'with' if use_recent else 'without'} recency)")

        return self.df_artifacts["tds_score"]


    def assign_tds_buckets(self) -> pd.DataFrame:
        
        if self.df_artifacts is None or self.df_artifacts.empty:
            raise ValueError("Artifact-level DataFrame is not loaded or is empty.")

        df = self.df_artifacts.copy()
        df = df[df["mean_tds"].notna()]

        
        bins = [-1, 0, 5, 20, 100, 500, float("inf")]
        labels = [
            "No Dependencies",
            "Very Lightweight",
            "Lightweight",
            "Moderate",
            "Heavy",
            "Bloated / Complex"
        ]
        tds_map = {label: i for i, label in enumerate(labels, 1)}

        
        df["tds_bucket"] = pd.cut(
            df["mean_tds"],
            bins=bins,
            labels=labels,
            include_lowest=True
        )
        df["tds_bucket_rank"] = df["tds_bucket"].map(tds_map)

        
        self.df_artifacts["tds_bucket"] = df["tds_bucket"]
        self.df_artifacts["tds_bucket_rank"] = df["tds_bucket_rank"]

        return self.df_artifacts



    def process_pagerank_scores(
        self,
        cap_pct: float = 99.9,
        mode: str = "log-clipped"
    ) -> pd.Series:
        if self.df is None:
            raise ValueError("Data not loaded. Run load_and_preprocess_data() first.")
        
        if mode == "log-clipped":
            
            cap_val = np.percentile(self.df["pagerank"], cap_pct)
            clipped_pr = self.df["pagerank"].clip(upper=cap_val)

            
            self.df["pr_score"] = np.log1p(clipped_pr)

            self.processing_stats.update({
                "pr_transform": "log-clipped (no scaling)",
                "pr_cap_pct": cap_pct,
                "pr_cap_value": cap_val,
            })
            print(f"PageRank processed (log-clipped mode, cap {cap_pct:.1f}%, cap_val={cap_val:.2f})")

        elif mode == "quantile":
            qt = QuantileTransformer(
                n_quantiles=min(10000, len(self.df)),
                output_distribution='uniform',
                subsample=100000
            )
            pr_values = self.df["pagerank"].values.reshape(-1, 1)
            self.df["pr_score"] = qt.fit_transform(pr_values).flatten()

            self.processing_stats.update({
                "pr_transform": "quantile (uniform)",
                "pr_n_quantiles": qt.n_quantiles_,
            })
            print(f"PageRank processed (quantile mode, uniform output)")

        elif mode == "log":
            self.df["pr_score"], cap_val = self._log_minmax(
                self.df["pagerank"], cap_pct
            )
            self.processing_stats.update({
                "pr_cap_pct": cap_pct,
                "pr_cap_value": cap_val,
                "pr_transform": "log-minmax",
            })
            print(f"PageRank processed (log mode, cap {cap_pct:.2f}%)")

        else:
            raise ValueError(f"Unknown mode: {mode}")

        return self.df["pr_score"]


    def assign_pagerank_buckets(self) -> pd.DataFrame:
        if self.df_artifacts is None or self.df_artifacts.empty:
            raise ValueError("Artifact-level DataFrame is not loaded or is empty.")

        df = self.df_artifacts.copy()
        df = df[df["mean_pagerank"].notna()]

        
        bins = [0.14, 0.15, 0.18, 0.25, 1.0, 10.0, float('inf')]
        labels = [
            "None",
            "Peripheral", 
            "Notable",
            "Core",
            "Important",
            "Elite"
        ]
        pr_map = {label: i for i, label in enumerate(labels, 1)}

        
        df["pr_bucket"] = pd.cut(
            df["mean_pagerank"],
            bins=bins,
            labels=labels,
            include_lowest=True
        )
        df["pr_bucket_rank"] = df["pr_bucket"].map(pr_map)

        
        self.df_artifacts["pr_bucket"] = df["pr_bucket"]
        self.df_artifacts["pr_bucket_rank"] = df["pr_bucket_rank"]
        return self.df_artifacts


    def calculate_freshness_scores(
        self,
        half_life_years: float = 2.0,
        missed_penalty: float = 0.20,
        combine: str = "combined",
        analysis_date: str = "2024-09-04",
        use_local_missed: bool = False,
        use_local_missed_within_tau: bool = True
    ) -> None:

        if self.df is None:
            raise ValueError("Data not loaded. Run load_and_preprocess_data() first.")

       
        if "release_days" not in self.df.columns:
            raise ValueError("Column 'release_days' is missing. Ensure data is preprocessed.")

        
        if isinstance(analysis_date, str):
            ref_dt = datetime.fromisoformat(analysis_date).replace(tzinfo=timezone.utc)
        elif isinstance(analysis_date, datetime):
            ref_dt = analysis_date.astimezone(timezone.utc)
        else:
            raise TypeError("analysis_date must be ISO string or datetime")

        
        self.df["age_days"] = np.maximum(self.df["release_days"], 0.5)
        age_days = self.df["age_days"].to_numpy(dtype=np.float32)

        
        λ = np.log(2) / (half_life_years * 365)
        temporal = np.exp(-λ * age_days)

        
        if missed_penalty == 0:
            missed_factor = np.ones_like(age_days)
            norm_type = "none"
        elif use_local_missed_within_tau:
            tau_days = half_life_years * 365
            release_days = self.df["release_days"].to_numpy(dtype=np.float32)
            missed = self.df["missed"].to_numpy(dtype=np.float32)
            artifact_codes = self.df["artifact_id"].astype("category").cat.codes.to_numpy(dtype=np.int32)
            max_missed_tau = compute_local_max_tau(
                release_days, missed, artifact_codes, int(tau_days)
            )
            missed_norm = missed / max_missed_tau
            missed_factor = 1.0 - missed_penalty * missed_norm
            norm_type = "artifact/τ"
        elif use_local_missed:
            missed = self.df["missed"].to_numpy(dtype=np.float32)
            artifact_max = self.df.groupby("artifact_id")["missed"].max()
            safe_max = artifact_max.reindex(self.df["artifact_id"]).fillna(1).to_numpy(dtype=np.float32)
            safe_max = np.where(safe_max == 0, 1, safe_max)
            missed_norm = missed / safe_max
            missed_factor = 1.0 - missed_penalty * missed_norm
            norm_type = "artifact"
        else:
            missed = self.df["missed"].to_numpy(dtype=np.float32)
            global_max = missed.max()
            divisor = global_max if global_max > 0 else 1
            missed_norm = missed / divisor
            missed_factor = 1.0 - missed_penalty * missed_norm
            norm_type = "global"

        
        self.df["freshness_age_only"] = np.clip(temporal, 0.0, 1.0)
        self.df["missed_penalty_factor"] = missed_factor
        self.df["freshness_score"] = np.clip(temporal * missed_factor, 0.0, 1.0)

        
        candidates = self.df[["artifact_id", "freshness_score", "release_timestamp"]].copy()
        candidates = candidates.sort_values(
            by=["artifact_id", "release_timestamp"],
            ascending=[True, False]  # Latest release first within each artifact
        )
        best = candidates.drop_duplicates(subset=["artifact_id"], keep="first")
        freshness_data = best.rename(columns={"freshness_score": "latest_freshness_score",
                                            "release_timestamp": "latest_release"})
        self.df_artifacts = self.df_artifacts.merge(freshness_data, on="artifact_id", how="left")


        
        stats = self.df["freshness_score"].describe()[["min", "mean", "max"]]
        print("  Freshness computed")
        print(f"half-life τ   : {half_life_years:.2f} years")
        print(f"decay λ       : {λ:.5f} day⁻¹")
        print(f"missed penalty: {missed_penalty:.2f} ({norm_type} norm)")
        print(f"score range   : {stats['min']:.4f} – {stats['max']:.4f}")
        print(f"mean score    : {stats['mean']:.4f}")

        
        self.processing_stats.update({
            'freshness_half_life_years': half_life_years,
            'freshness_missed_penalty': missed_penalty,
            'freshness_combine': combine,
            'freshness_norm_type': norm_type,
            'freshness_lambda': λ
        })



    def assign_freshness_buckets(self) -> pd.DataFrame:

        if self.df_artifacts is None or self.df_artifacts.empty:
            raise ValueError("Artifact-level DataFrame is not loaded or is empty.")
        
        df = self.df_artifacts.copy()
        
        
        bins = [0.0, 0.2, 0.45, 0.70, 0.95, 1.0]
        labels = ["Stale", "Aging", "Maintained", "Fresh", "Freshest"]
        label_to_rank = {label: i for i, label in enumerate(labels, 1)}

        
        df["freshness_bucket"] = pd.cut(
            df["latest_freshness_score"],
            bins=bins,
            labels=labels,
            include_lowest=True
        )

        
        df["freshness_bucket_rank"] = df["freshness_bucket"].map(label_to_rank)

        
        self.df_artifacts["freshness_bucket"] = df["freshness_bucket"]
        self.df_artifacts["freshness_bucket_rank"] = df["freshness_bucket_rank"]

        return self.df_artifacts

  

    # ========================================================================
    # 5. ANALYSIS AND VISUALIZATION
    # ========================================================================


    def view_cluster_members(
        self,
        cluster_col: str = "kmodes_cluster",
        cluster_ids: list[int] = None,
        top_n: int = 10,
        extra_columns: list[str] = None,
        sort_by: str = "total_cve_count",
        ascending: bool = False
    ) -> dict[int, pd.DataFrame]:

        if cluster_col not in self.df_artifacts.columns:
            raise ValueError(f"{cluster_col!r} not found in artifacts DataFrame.")

        df = self.df_artifacts.copy()
        base_cols = [
            "artifact_id", "total_cve_count", "has_recent_cve",
            "pr_bucket", "tds_bucket", "freshness_bucket",
            "cve_count_bucket", "cve_severity_bucket"
        ]
        all_cols = list(dict.fromkeys(base_cols + (extra_columns or [])))

        cluster_ids = cluster_ids or sorted(df[cluster_col].dropna().unique())
        results = {}

        for cluster_id in cluster_ids:
            df_cluster = df[df[cluster_col] == cluster_id]
            if df_cluster.empty:
                continue

            df_cluster = df_cluster.sort_values(by=sort_by, ascending=ascending)
            final_df = df_cluster[all_cols].head(top_n)
            results[cluster_id] = final_df

            print(f"\nTop {top_n} artifacts in cluster {cluster_id}")
            display(final_df)

        return results


    def preview_cluster_releases(
        self,
        cluster_col: str = "kmodes_cluster",
        cluster_ids: list[int] | None = None,
        per_cluster: int = 10,
        release_columns: list[str] | None = None,
        sort_by: str = "release_timestamp",
        ascending: bool = False,
        random_sample: bool = False,
    ) -> dict[int, pd.DataFrame]:
        if self.df is None or self.df.empty:
            raise ValueError("Release-level DataFrame `df` is not loaded. Run load_and_preprocess_data() first.")
        if self.df_artifacts is None or self.df_artifacts.empty:
            raise ValueError("Artifact-level DataFrame `df_artifacts` is not loaded.")
        if cluster_col not in self.df_artifacts.columns:
            raise ValueError(f"{cluster_col!r} not found in artifacts DataFrame.")

        
        default_cols = [
            "artifact_id",
            "gav",
            "release_timestamp",
            "pagerank",
            "tds_core",
            "has_cve",
            "cve_count",
            "max_severity",
            "age_days",
        ]
        if release_columns is None:
            release_columns = default_cols

        
        key_cols = ["artifact_id", cluster_col]
        artifact_clusters = self.df_artifacts[key_cols].dropna(subset=[cluster_col])
        releases_with_cluster = self.df.merge(artifact_clusters, on="artifact_id", how="inner")

        
        cluster_ids = cluster_ids or sorted(pd.unique(releases_with_cluster[cluster_col]))

        
        available_cols = [c for c in release_columns if c in releases_with_cluster.columns]
        cols = list(dict.fromkeys([cluster_col] + available_cols))

        results: dict[int, pd.DataFrame] = {}
        for cid in cluster_ids:
            sub = releases_with_cluster[releases_with_cluster[cluster_col] == cid]
            if sub.empty:
                continue

            df_view = sub[cols]
            if random_sample:
                df_out = df_view.sample(n=min(per_cluster, len(df_view)), random_state=42)
            else:
                if sort_by in df_view.columns:
                    df_out = df_view.sort_values(by=sort_by, ascending=ascending).head(per_cluster)
                else:
                    
                    if "release_timestamp" in df_view.columns:
                        df_out = df_view.sort_values(by="release_timestamp", ascending=ascending).head(per_cluster)
                    else:
                        df_out = df_view.head(per_cluster)

            results[int(cid)] = df_out
            print(f"\nPreviewing {len(df_out)} releases for cluster {cid}")
            display(df_out)

        return results

    def analyse_tds_distribution(self) -> Dict[str, Any]:

        if self.df is None:
            raise ValueError("Data not loaded. Run load_and_preprocess_data() first.")
        
        tds_values = self.df['tds_core'].values
        conditions = [
            tds_values == 0,
            tds_values < 10,
            tds_values < 100,
            tds_values < 1000
        ]
        choices = ['Zero TDS', 'Low TDS', 'Medium TDS', 'High TDS']
        
        self.df['tds_category'] = np.select(conditions, choices, default='Very High TDS')
        
        
        percentiles = np.percentile(tds_values, [95, 99, 99.9])
        analysis = {
            'total_packages': len(self.df),
            'zero_tds_packages': (tds_values == 0).sum(),
            'max_tds': tds_values.max(),
            'mean_tds': tds_values.mean(),
            'median_tds': np.median(tds_values),
            'tds_categories': self.df['tds_category'].value_counts().to_dict(),
            'percentiles': {
                '95th': percentiles[0],
                '99th': percentiles[1],
                '99.9th': percentiles[2]
            }
        }
        
        return analysis


    
    
    # ========================================================================
    # 6. PFEIFFER'S WORK REPLICATION METHODS
    # ========================================================================
    def create_pfeiffer_table_i(self, top_n: int = 20, use_raw_pagerank: bool = True) -> pd.DataFrame:

        
        required_cols = ['artifact_id', 'mean_pagerank', 'truck_factor', 'criticality_score_pf']
        missing_cols = [col for col in required_cols if col not in self.df_artifacts.columns]
        if missing_cols:
            raise ValueError(f"Missing required columns in df_artifacts: {missing_cols}")

        
        valid_rows = self.df_artifacts[
            (self.df_artifacts['truck_factor'].notna()) &
            (self.df_artifacts['criticality_score_pf'].notna()) &
            (self.df_artifacts['criticality_score_pf'] != -1)
        ]

        
        pr_col = 'mean_pagerank' if use_raw_pagerank else 'normalized_pagerank'
        top_df = valid_rows.nlargest(top_n, pr_col)

        
        table = top_df[['artifact_id', pr_col, 'truck_factor', 'criticality_score_pf']].rename(columns={
            'artifact_id': 'Name',
            pr_col: 'PR',
            'truck_factor': 'TF',
            'criticality_score_pf': 'CS'
        })

        return table
    
    def create_pfeiffer_table_ii(self, top_n: int = 20) -> pd.DataFrame:

        df = self.df_artifacts.copy()

        df = df[
            df[['depth1_cnt', 'depth2_cnt', 'depth3_cnt']].notna().all(axis=1)
        ].copy()

        df["pct_total_d1"] = 100 * df["depth1_cnt"] / TOTAL_RELEASES
        df["pct_conn_d1"] = 100 * df["depth1_cnt"] / CONNECTED_RELEASES

        df["pct_total_d2"] = 100 * df["depth2_cnt"] / TOTAL_RELEASES
        df["pct_conn_d2"] = 100 * df["depth2_cnt"] / CONNECTED_RELEASES

        df["pct_total_d3"] = 100 * df["depth3_cnt"] / TOTAL_RELEASES
        df["pct_conn_d3"] = 100 * df["depth3_cnt"] / CONNECTED_RELEASES

        top_df = df.nlargest(top_n, 'depth1_cnt').copy()

        def format_cell(count, pct1, pct2):
            return f"{int(count):,}  {pct1:.0f}% (<small>{pct2:.0f}%</small>)"

        table = pd.DataFrame({
            "Name": top_df["artifact_id"],
            "◦→◦": [
                format_cell(c, p1, p2)
                for c, p1, p2 in zip(top_df["depth1_cnt"], top_df["pct_total_d1"], top_df["pct_conn_d1"])
            ],
            "◦−[1..2]→◦": [
                format_cell(c, p1, p2)
                for c, p1, p2 in zip(top_df["depth2_cnt"], top_df["pct_total_d2"], top_df["pct_conn_d2"])
            ],
            "◦−[1..3]→◦": [
                format_cell(c, p1, p2)
                for c, p1, p2 in zip(top_df["depth3_cnt"], top_df["pct_total_d3"], top_df["pct_conn_d3"])
            ],
        })

        return table

    


    def create_artifact_dependents_table(self, csv_path: str = ARTIFACT_DEPENDENTS_PATH, top_n: int = 20) -> pd.DataFrame:

        try:
            artifact_deps = pd.read_csv(csv_path)
        except FileNotFoundError:
            raise FileNotFoundError(f"CSV file not found: {csv_path}")
        
        required_cols = ['target_artifact', 'depth_1', 'depth_2', 'depth_3']
        missing_cols = [col for col in required_cols if col not in artifact_deps.columns]
        if missing_cols:
            raise ValueError(f"Missing required columns in CSV: {missing_cols}")

        artifact_deps = artifact_deps.copy()
        artifact_deps["pct_total_d1"] = 100 * artifact_deps["depth_1"] / TOTAL_ARTIFACTS
        artifact_deps["pct_conn_d1"] = 100 * artifact_deps["depth_1"] / CONNECTED_ARTIFACTS
        
        artifact_deps["pct_total_d2"] = 100 * artifact_deps["depth_2"] / TOTAL_ARTIFACTS
        artifact_deps["pct_conn_d2"] = 100 * artifact_deps["depth_2"] / CONNECTED_ARTIFACTS
        
        artifact_deps["pct_total_d3"] = 100 * artifact_deps["depth_3"] / TOTAL_ARTIFACTS
        artifact_deps["pct_conn_d3"] = 100 * artifact_deps["depth_3"] / CONNECTED_ARTIFACTS
        
        if top_n and top_n < len(artifact_deps):
            top_df = artifact_deps.nlargest(top_n, 'depth_3').copy()
        else:
            top_df = artifact_deps.sort_values('depth_3', ascending=False).copy()
        
        def format_cell(count, pct1, pct2):
            return f"{int(count):,}  {pct1:.1f}% (<small>{pct2:.1f}%</small>)"
        
        table = pd.DataFrame({
            "Artifact": top_df["target_artifact"],
            "◦→◦": [
                format_cell(c, p1, p2)
                for c, p1, p2 in zip(top_df["depth_1"], top_df["pct_total_d1"], top_df["pct_conn_d1"])
            ],
            "◦−[1..2]→◦": [
                format_cell(c, p1, p2)
                for c, p1, p2 in zip(top_df["depth_2"], top_df["pct_total_d2"], top_df["pct_conn_d2"])
            ],
            "◦−[1..3]→◦": [
                format_cell(c, p1, p2)
                for c, p1, p2 in zip(top_df["depth_3"], top_df["pct_total_d3"], top_df["pct_conn_d3"])
            ],
        })
        
        table.index = range(1, len(table) + 1)
        
        return table

    def compute_correlations(self) -> pd.DataFrame:

        required_cols = ['mean_pagerank', 'truck_factor', 'criticality_score_pf']
        missing_cols = [col for col in required_cols if col not in self.df_artifacts.columns]
        if missing_cols:
            raise ValueError(f"Missing required columns in df_artifacts: {missing_cols}")

        valid_rows = self.df_artifacts[
            (self.df_artifacts['mean_pagerank'].notna()) &
            (self.df_artifacts['truck_factor'].notna()) &
            (self.df_artifacts['truck_factor'] > 0) &
            (self.df_artifacts['criticality_score_pf'].notna()) &
            (self.df_artifacts['criticality_score_pf'] != -1)
        ].copy()

        n = len(valid_rows)
        print(f"Spearman correlations sample size (n): {n}")

        pr_cs_corr, pr_cs_pval = spearmanr(valid_rows['mean_pagerank'], valid_rows['criticality_score_pf'])

        tf_cs_corr, tf_cs_pval = spearmanr(valid_rows['truck_factor'], valid_rows['criticality_score_pf'])

        
        pr_cs_corr = round(pr_cs_corr, 4)
        tf_cs_corr = round(tf_cs_corr, 4)

        def _format_p_value(p: float) -> str:
            if pd.isna(p):
                return ''
            if p < 1e-6:
                return '<1e-6'
            if p < 1e-3:
                return '<0.001'
            return f"{p:.3f}"

        
        pfeiffer_results = [
            {
                'Metric Pair': 'PR vs CS',
                'Source': 'Pfeiffer',
                'Spearman Coefficient (ρ)': 0.0346,
                'p-value': 0.7436,
                'p': _format_p_value(0.7436),
                'n': 92,
            },
            {
                'Metric Pair': 'TF vs CS',
                'Source': 'Pfeiffer',
                'Spearman Coefficient (ρ)': 0.5416,
                'p-value': np.nan,
                'p': '<0.05',
                'n': 92,
            },
        ]

        
        computed_results = [
            {
                'Metric Pair': 'PR vs CS',
                'Source': 'Computed',
                'Spearman Coefficient (ρ)': pr_cs_corr,
                'p-value': pr_cs_pval,
                'p': _format_p_value(pr_cs_pval),
                'n': n,
            },
            {
                'Metric Pair': 'TF vs CS',
                'Source': 'Computed',
                'Spearman Coefficient (ρ)': tf_cs_corr,
                'p-value': tf_cs_pval,
                'p': _format_p_value(tf_cs_pval),
                'n': n,
            },
        ]

        
        comparison_table = pd.DataFrame(computed_results + pfeiffer_results)

        return comparison_table


 


    def plot_distribution(
        self,
        column: str,
        source: str = "release",  
        clip_percentile: float = 99.9,
        bins: int = 100,
        figsize: Tuple[int, int] = (10, 5),
        title: Optional[str] = None,
        xlabel: Optional[str] = None,
        log_y: bool = True
    ) -> plt.Figure:

        if source == "artifact":
            df = self.df_artifacts
            label = "Artifact-level"
        elif source == "release":
            df = self.df
            label = "Release-level"
        else:
            raise ValueError("source must be 'artifact' or 'release'")

        if df is None or df.empty:
            raise ValueError(f"{label} data not loaded.")

        if column not in df.columns:
            raise ValueError(f"Column '{column}' not found in {label} data.")

        values = df[column].dropna()
        clip_value = np.percentile(values, clip_percentile)
        clipped = values.clip(upper=clip_value)

        fig, ax = plt.subplots(figsize=figsize)
        ax.hist(clipped, bins=bins, color='skyblue', edgecolor='black', alpha=0.8)
        ax.axvline(clip_value, color='red', linestyle='--', linewidth=1,
                label=f'{clip_percentile}th percentile ({clip_value:.2f})')

        ax.set_title(title or f'{label} {column} Distribution', fontsize=13)
        ax.set_xlabel(xlabel or column.replace('_', ' ').title(), fontsize=11)
        ax.set_ylabel('Frequency (Log Scale)' if log_y else 'Frequency', fontsize=11)
        if log_y:
            ax.set_yscale('log')
        ax.legend()
        ax.grid(True, which='both', linestyle=':', linewidth=0.5)

        plt.tight_layout()
        return fig


   


    def plot_bucket_counts(
        self,
        bucket_col: str,
        title: str = None,
        bucket_order: list[str] = None,
        color: str = "steelblue",
        log_scale: bool = False  
    ) -> plt.Figure:

        if bucket_col not in self.df_artifacts.columns:
            raise ValueError(f"{bucket_col!r} not found in DataFrame.")

        counts = self.df_artifacts[bucket_col].value_counts()
        if bucket_order:
            counts = counts.reindex(bucket_order)

        fig, ax = plt.subplots(figsize=(10, 5))
        counts.plot(kind="bar", color=color, edgecolor="black", ax=ax)

        ax.set_title(title or f"Artifact Counts per {bucket_col}", fontsize=14)
        ax.set_ylabel("Number of Artifacts", fontsize=12)
        ax.set_xlabel(bucket_col.replace("_", " ").title(), fontsize=12)
        ax.grid(axis="y", linestyle=":", alpha=0.7)

        if log_scale:
            ax.set_yscale("log")  
        plt.xticks(rotation=30, ha="right")
        plt.tight_layout()

        return fig



    



    def describe_groups(
        self,
        groups: list[dict]
    ) -> pd.DataFrame:

        results = []

        for group in groups:
            name = group.get("name", "Unnamed")
            filters = group.get("filters", {})
            df = self.df_artifacts.copy()

            
            mask = pd.Series(True, index=df.index)
            for col, values in filters.items():
                mask &= df[col].isin(values)

            filtered_df = df[mask]
            if filtered_df.empty:
                print(f"Group '{name}' has no matching artifacts.")
                continue

            results.append({
                "group": name,
                "count": len(filtered_df),
                "%_with_CVE": round(filtered_df["has_cve"].mean() * 100, 2),
                "avg_CVE_count": round(filtered_df["total_cve_count"].mean(), 2),
                "%_with_recent_CVE": round(filtered_df["has_recent_cve"].mean() * 100, 2),
                "avg_recent_CVE_count": round(filtered_df["total_recent_cve_count"].mean(), 2),
                "avg_pagerank": round(filtered_df["mean_pagerank"].mean(), 6),
                "avg_tds": round(filtered_df["mean_tds"].mean(), 3),
            })

        df_summary = pd.DataFrame(results)

        
        desired_cols = [
            "group", "count",
            "%_with_CVE", "avg_CVE_count",
            "%_with_recent_CVE", "avg_recent_CVE_count",
            "avg_pagerank", "avg_tds"
        ]
        return df_summary[desired_cols]
    
    def assign_cve_buckets(self) -> pd.DataFrame:
        if self.df_artifacts is None or self.df_artifacts.empty:
            raise ValueError("Artifact-level DataFrame is not loaded or is empty.")

        df = self.df_artifacts.copy()
        df = df[df["total_cve_count"].notna()]

        
        severity_map = {
            "NONE": 0,
            "LOW": 1,
            "MODERATE": 2,
            "HIGH": 3,
            "CRITICAL": 4
        }

        
        severity_bins = [-1, 0, 1, 2, 3, 4]
        severity_labels = ["NONE", "LOW", "MODERATE", "HIGH", "CRITICAL"]
        severity_label_to_rank = {label: i for i, label in enumerate(severity_labels)}

        df["severity_score"] = df["predominant_max_severity"].map(severity_map)
        df["cve_severity_bucket"] = pd.cut(
            df["severity_score"],
            bins=severity_bins,
            labels=severity_labels
        )
        df["cve_severity_bucket_rank"] = df["cve_severity_bucket"].map(severity_label_to_rank)

        
        count_bins = [-1, 0, 1, 2, 5, 10, float("inf")]
        count_labels = ["None", "1", "2", "3-5", "6-10", "10+"]
        count_label_to_rank = {label: i for i, label in enumerate(count_labels)}

        df["cve_count_bucket"] = pd.cut(
            df["total_cve_count"],
            bins=count_bins,
            labels=count_labels
        )
        df["cve_count_bucket_rank"] = df["cve_count_bucket"].map(count_label_to_rank)

        
        df["recent_cve_ratio"] = df["total_recent_cve_count"] / df["total_cve_count"].replace(0, np.nan)
        df["recent_cve_ratio"] = df["recent_cve_ratio"].fillna(0)

        
        self.df_artifacts["cve_severity_bucket"] = df["cve_severity_bucket"]
        self.df_artifacts["cve_severity_bucket_rank"] = df["cve_severity_bucket_rank"]
        self.df_artifacts["cve_count_bucket"] = df["cve_count_bucket"]
        self.df_artifacts["cve_count_bucket_rank"] = df["cve_count_bucket_rank"]
        self.df_artifacts["recent_cve_ratio"] = df["recent_cve_ratio"]

        return self.df_artifacts




    def plot_pagerank_bucket_counts(self) -> plt.Figure:
        
        if "pr_bucket" not in self.df_artifacts.columns:
            raise ValueError("Call assign_pagerank_buckets() before plotting.")
        bucket_order = list(self.df_artifacts["pr_bucket"].cat.categories)      
        bucket_counts = self.df_artifacts['pr_bucket'].value_counts().reindex(bucket_order)  
        fig, ax = plt.subplots(figsize=(10, 5))
        bucket_counts.plot(kind='bar', color='steelblue', edgecolor='black', ax=ax)

        ax.set_title("Artifact Counts per PageRank Bucket", fontsize=14)
        ax.set_ylabel("Number of Artifacts", fontsize=12)
        ax.set_xlabel("PageRank Bucket", fontsize=12)
        ax.grid(axis='y', linestyle=':', alpha=0.7)
        plt.xticks(rotation=30, ha='right')
        plt.tight_layout()
        return fig
    

    def plot_artifact_metric_histogram(
        self,
        artifact_id: Optional[str] = None,
        gav: Optional[str] = None,
        metric: str = "tds_core",
        bins: int = 30,
        by_year: bool = False,
        max_years: int = 6,
        density: bool = False,
    ) -> plt.Figure:

        if self.df is None or self.df.empty:
            raise ValueError("Release-level DataFrame `df` is not loaded. Run load_and_preprocess_data() first.")

        if metric not in self.df.columns:
            raise ValueError(f"Metric '{metric}' not found in release-level DataFrame.")

        if artifact_id is None and gav is None:
            raise ValueError("Provide either artifact_id or gav.")

        
        df_rel = self.df
        if artifact_id is not None:
            
            key = str(artifact_id).strip().lower()
            df_rel = df_rel[df_rel["artifact_id"].astype(str).str.strip().str.lower() == key]
        else:
            df_rel = df_rel[df_rel["gav"] == gav]

        if df_rel.empty:
            raise ValueError("No releases found for the specified artifact.")

        
        df_rel = df_rel[["release_timestamp", metric, "gav"]].dropna(subset=[metric]).copy()
        if "release_timestamp" in df_rel.columns and pd.api.types.is_datetime64_any_dtype(df_rel["release_timestamp"]):
            df_rel["release_year"] = df_rel["release_timestamp"].dt.year
        else:
            df_rel["release_year"] = np.nan

        
        df_rel = df_rel.sort_values("release_timestamp")

        if not by_year:
            
            fig, ax = plt.subplots(figsize=(12, 6))
            
            
            ax.plot(df_rel["release_timestamp"], df_rel[metric], 
                   marker='o', linewidth=2, markersize=4, color="steelblue", alpha=0.8)
            
            
            ax.fill_between(df_rel["release_timestamp"], df_rel[metric], 0, alpha=0.3, color="steelblue")
            
            
            ax.set_ylim(bottom=0)
            
            
            artifact_name = artifact_id if artifact_id else gav
            ax.set_title(f"{metric} evolution over time for {artifact_name}", fontsize=14, fontweight='bold')
            ax.set_xlabel("Release Date", fontsize=12)
            ax.set_ylabel(f"{metric} Value", fontsize=12)
            
            
            ax.tick_params(axis='x', rotation=45)
            
            
            ax.grid(True, linestyle=":", alpha=0.6)
            
            
            ax.text(0.02, 0.98, f"Total releases: {len(df_rel)}", 
                   transform=ax.transAxes, fontsize=10, verticalalignment='top',
                   bbox=dict(boxstyle='round', facecolor='white', alpha=0.8))
            
            plt.tight_layout()
            return fig

        
        stat = "density" if density else "count"
        year_counts = (
            df_rel.dropna(subset=["release_year"])
            .groupby("release_year").size().sort_values(ascending=False)
        )
        top_years = list(year_counts.head(max_years).index)
        df_facet = df_rel[df_rel["release_year"].isin(top_years)].copy()
        if df_facet.empty:
            
            fig, ax = plt.subplots(figsize=(9, 5))
            sns.histplot(data=df_rel, x=metric, bins=bins, stat=stat, color="steelblue", edgecolor="black", ax=ax)
            ax.set_title(f"{metric} distribution for artifact", fontsize=13)
            ax.set_xlabel(metric)
            ax.set_ylabel("Density" if density else "Count")
            ax.grid(axis="y", linestyle=":", alpha=0.6)
            plt.tight_layout()
            return fig

        g = sns.FacetGrid(df_facet, col="release_year", col_wrap=min(3, max_years), sharex=True, sharey=False, height=3)
        g.map(sns.histplot, metric, bins=bins, stat=stat, color="steelblue", edgecolor="black")
        g.set_axis_labels(metric, "Density" if density else "Count")
        g.set_titles("{col_name}")
        for ax in g.axes.flatten():
            ax.grid(axis="y", linestyle=":", alpha=0.6)
        g.fig.suptitle(f"{metric} distribution by year", y=1.02, fontsize=13)
        plt.tight_layout()
        return g.fig

    def summarise_buckets(
        self,
        bucket_cols=("pr_bucket", "tds_bucket", "freshness_bucket"),
        as_percent: bool = True,
        bucket_order: dict[str, list[str]] | None = None,
    ) -> dict[str, pd.DataFrame]:
        pct = (lambda s: s.mul(100).round(2)) if as_percent else (lambda s: s.round(4))
        summaries = {}

        for col in bucket_cols:
            if col not in self.df_artifacts.columns:
                raise ValueError(f"Missing bucket column: {col}")

            base = self.df_artifacts

            counts = base[col].value_counts(dropna=False).to_frame("artifact_count")

            prevalence = (
                base.groupby(col)["has_cve"].mean()
                .pipe(pct)
                .rename("%_with_CVE" if as_percent else "prop_with_CVE")
                .to_frame()
            )

            mean_cnt = (
                base.groupby(col)["total_cve_count"].mean()
                .round(2)
                .rename("avg_CVE_count")
                .to_frame()
            )

            recent_prev = (
                base.groupby(col)["has_recent_cve"].mean()
                .pipe(pct)
                .rename("%_with_recent_CVE" if as_percent else "prop_with_recent_CVE")
                .to_frame()
            )

            mean_recent = (
                base.groupby(col)["total_recent_cve_count"].mean()
                .round(2)
                .rename("avg_recent_CVE_count")
                .to_frame()
            )

            severity_mix = (
                base.groupby(col)["predominant_max_severity"]
                .value_counts(normalize=True)
                .pipe((lambda s: s.mul(100).round(2)) if as_percent else (lambda s: s.round(4)))
                .rename("share_" + ("%" if as_percent else "prop"))
                .unstack(fill_value=0)
            )

            summary = (
                counts.join(prevalence, how="left")
                    .join(mean_cnt,  how="left")
                    .join(recent_prev, how="left")
                    .join(mean_recent, how="left")
                    .join(severity_mix, how="left")
            )

            
            if bucket_order and col in bucket_order:
                summary = summary.reindex(bucket_order[col])

            
            preferred = [
                "artifact_count",
                "%_with_CVE" if as_percent else "prop_with_CVE",
                "avg_CVE_count",
                "%_with_recent_CVE" if as_percent else "prop_with_recent_CVE",
                "avg_recent_CVE_count",
            ]
            other = [c for c in summary.columns if c not in preferred]
            summary = summary[preferred + sorted(other)]

            summaries[col] = summary

        return summaries



    def summarise_cve_buckets(self) -> dict[str, pd.DataFrame]:

        summaries = {}
        for col in ["cve_count_bucket", "cve_severity_bucket"]:
            df = self.df_artifacts.copy()

            
            df = df[df[col].notna()]

            
            counts = df[col].value_counts(dropna=False).to_frame("artifact_count")

            
            recent_prevalence = (
                df.groupby(col)["has_recent_cve"].mean().mul(100).round(2)
                .rename("%_with_recent_CVE")
                .to_frame()
            )

            
            mean_recent = (
                df.groupby(col)["total_recent_cve_count"].mean().round(2)
                .rename("avg_recent_CVE_count")
                .to_frame()
            )

            
            mean_total = (
                df.groupby(col)["total_cve_count"].mean().round(2)
                .rename("avg_CVE_count")
                .to_frame()
            )

            summary = (
                counts
                .join(mean_total, how="left")
                .join(recent_prevalence, how="left")
                .join(mean_recent, how="left")
            )

            summaries[col] = summary

        return summaries

    def create_archetype_groups(self) -> dict[str, pd.DataFrame]:
        
        if self.df_artifacts is None or self.df_artifacts.empty:
            raise ValueError("Artifact-level DataFrame is not loaded or is empty.")

        
        groups = {
            "Foundational": {
                "pr_bucket": ["Elite"],
                "freshness_bucket": ["Freshest"],
                "tds_bucket": ["No Dependencies", "Very Lightweight"]
            },
            "Mainstream": {
                "pr_bucket": ["Important"],
                "freshness_bucket": ["Fresh", "Freshest"],
                "tds_bucket": ["Moderate"]
            },
            "Complex": {
                "pr_bucket": ["Elite", "Important"],
                "tds_bucket": ["Heavy", "Bloated / Complex"]
            }
        }

        results = {}
        for group_name, filters in groups.items():
            df = self.df_artifacts.copy()
            mask = pd.Series(True, index=df.index)
            
            
            for col, values in filters.items():
                if col in df.columns:
                    mask &= df[col].isin(values)
            
            filtered_df = df[mask]
            results[group_name] = filtered_df
            
            print(f"\n{group_name} Group: {len(filtered_df):,} artifacts")
            
        return results

    def create_cross_tabulation(
        self,
        row_bucket: str,
        col_bucket: str,
        normalize: str = "columns",
        as_percent: bool = True,
        row_order: list[str] = None,
        col_order: list[str] = None
    ) -> pd.DataFrame:

        if self.df_artifacts is None or self.df_artifacts.empty:
            raise ValueError("Artifact-level DataFrame is not loaded or is empty.")
            
        crosstab = pd.crosstab(
            self.df_artifacts[row_bucket], 
            self.df_artifacts[col_bucket],
            normalize=normalize
        )
        
        if as_percent:
            crosstab = crosstab * 100
            crosstab = crosstab.round(2)
        else:
            crosstab = crosstab.round(4)
            
        if row_order:
            available_rows = [r for r in row_order if r in crosstab.index]
            crosstab = crosstab.reindex(available_rows)
            
        if col_order:
            available_cols = [c for c in col_order if c in crosstab.columns]
            crosstab = crosstab.reindex(columns=available_cols)
            
        return crosstab

    def create_archetype_groups_table(self) -> pd.DataFrame:

        if self.df_artifacts is None or self.df_artifacts.empty:
            raise ValueError("Artifact-level DataFrame is not loaded or is empty.")
        
        total_artifacts = len(self.df_artifacts)
        
        clusters = {
            "Foundational": {
                "definition": "Elite × Freshest × (None ∪ Very-Lightweight)",
                "filters": {
                    "pr_bucket": ["Elite"],
                    "freshness_bucket": ["Freshest"], 
                    "tds_bucket": ["No Dependencies", "Very Lightweight"]
                }
            },
            "Mainstream": {
                "definition": "Important × (Fresh ∪ Freshest) × Moderate", 
                "filters": {
                    "pr_bucket": ["Important"],
                    "freshness_bucket": ["Fresh", "Freshest"],
                    "tds_bucket": ["Moderate"]
                }
            },
            "Complex": {
                "definition": "(Elite ∪ Important) × (Stale ∪ Aging ∪ Maintained) × Bloated/Complex",
                "filters": {
                    "pr_bucket": ["Elite", "Important"],
                    "tds_bucket": ["Bloated / Complex"],
                    "freshness_bucket": ["Stale", "Aging", "Maintained"]
                }
            }
        }
        
        results = []
        
        for cluster_name, cluster_info in clusters.items():
            df = self.df_artifacts.copy()
            mask = pd.Series(True, index=df.index)
            
            for col, values in cluster_info["filters"].items():
                if col in df.columns:
                    mask &= df[col].isin(values)
            
            filtered_df = df[mask]
            count = len(filtered_df)
            percentage = (count / total_artifacts) * 100
            
            results.append({
                "Cluster": cluster_name,
                "Definition (PR × Freshness × TDS)": cluster_info["definition"],
                "n": f"{count:,}",
                "% of artefacts": f"{percentage:.3f}%"
            })
        
        clusters_table = pd.DataFrame(results)
        
        return clusters_table

    def preview_archetype_groups(
        self,
        clusters: list[str] = None,
        top_n: int = 10,
        sort_by: str = "mean_pagerank",
        ascending: bool = False,
        extra_columns: list[str] = None,
        include_cve: bool = False
    ) -> dict[str, pd.DataFrame]:

        if self.df_artifacts is None or self.df_artifacts.empty:
            raise ValueError("Artifact-level DataFrame is not loaded or is empty.")
        
        cluster_definitions = {
            "Foundational": {
                "pr_bucket": ["Elite"],
                "freshness_bucket": ["Freshest"], 
                "tds_bucket": ["No Dependencies", "Very Lightweight"]
            },
            "Mainstream": {
                "pr_bucket": ["Important"],
                "freshness_bucket": ["Fresh", "Freshest"],
                "tds_bucket": ["Moderate"]
            },
            "Complex": {
                "pr_bucket": ["Elite", "Important"],
                "tds_bucket": ["Bloated / Complex"],
                "freshness_bucket": ["Stale", "Aging", "Maintained"]
            }
        }
        
        base_columns = [
            "artifact_id", 
            "mean_pagerank", 
            "mean_tds",
            "latest_release",
            "pr_bucket", 
            "tds_bucket", 
            "freshness_bucket"
        ]
        
        if include_cve:
            base_columns.extend([
                "total_cve_count", 
                "has_recent_cve"
            ])
        
        if extra_columns:
            base_columns.extend(extra_columns)
        
        all_columns = list(dict.fromkeys(base_columns))
        
        clusters_to_show = clusters or list(cluster_definitions.keys())
        
        results = {}
        
        for cluster_name in clusters_to_show:
            if cluster_name not in cluster_definitions:
                print(f"Unknown cluster: {cluster_name}")
                continue
                
            filters = cluster_definitions[cluster_name]
            df = self.df_artifacts.copy()
            mask = pd.Series(True, index=df.index)
            
            # Apply all filters
            for col, values in filters.items():
                if col in df.columns:
                    mask &= df[col].isin(values)
            
            filtered_df = df[mask]
            
            if filtered_df.empty:
                print(f"\n {cluster_name} Cluster: No matching artifacts")
                continue
            
            available_cols = [col for col in all_columns if col in filtered_df.columns]
            
            if sort_by in filtered_df.columns:
                sorted_df = filtered_df.sort_values(by=sort_by, ascending=ascending)
            else:
                sorted_df = filtered_df
                
            preview_df = sorted_df[available_cols].head(top_n)
            
            if 'latest_release' in preview_df.columns:
                preview_df = preview_df.copy()
                preview_df['latest_release'] = preview_df['latest_release'].dt.strftime("%Y-%m-%d")
            
            results[cluster_name] = preview_df
            
            print(f"\n {cluster_name} Cluster - Top {len(preview_df)} artifacts (sorted by {sort_by})")
            print(f"   Total artifacts in cluster: {len(filtered_df):,}")
            display(preview_df.reset_index(drop=True))
        
        return results
    
    def plot_freshness_distribution(self, figsize: Tuple[int, int] = (10, 5)) -> None:

        if self.df is None:
            raise ValueError("Data not loaded. Run load_and_preprocess_data() first.")

        if 'freshness_score' not in self.df.columns or 'freshness_age_only' not in self.df.columns:
            raise ValueError("Freshness scores not calculated. Run calculate_freshness_scores() first.")

        cox = self.df['freshness_score'].dropna().values.ravel()
        temporal = self.df['freshness_age_only'].dropna().values.ravel()

        plt.figure(figsize=figsize)

        plt.hist(
            temporal,
            bins=100,
            alpha=0.9,
            label='Temporal Freshness',
            color='orange',
            edgecolor='black'
        )

        plt.hist(
            cox,
            bins=100,
            alpha=0.7,
            color='steelblue',
            label='Temporal Freshness + Version Penalty'
        )

        plt.title("Release-Level Freshness Score Distributions")
        plt.xlabel("Freshness (MinMax Scaled)")
        plt.ylabel("Frequency")
        plt.legend(loc='upper left')
        plt.tight_layout()
        plt.show()


 
    def view_groups(
        self,
        group_definitions: list[dict],
        group_names: list[str] = None,
        top_n: int = 10,
        extra_columns: list[str] = None,
        sort_by: Union[str, list[str], None] = None,
        ascending: bool = False
    ) -> dict[str, pd.DataFrame]:

        core_cols = ["artifact_id", "total_cve_count", "has_recent_cve"]
        results = {}
        group_names = group_names or [g.get("name") for g in group_definitions]

        for group in group_definitions:
            name = group.get("name")
            if name not in group_names:
                continue

            filters = group.get("filters", {})
            df = self.df_artifacts.copy()
            mask = pd.Series(True, index=df.index)

            for col, values in filters.items():
                mask &= df[col].isin(values)

            df_filtered = df[mask]
            if df_filtered.empty:
                print(f"\n⚠ No matching artifacts for group: {name}")
                continue

            if sort_by is None:
                sort_priority = []
                for col in filters.keys():
                    if col == "pr_bucket":
                        sort_priority.append("mean_pagerank")
                    elif col == "tds_bucket":
                        sort_priority.append("mean_tds")
                    elif col == "freshness_bucket":
                        sort_priority.append("latest_release")
                if not sort_priority:
                    sort_priority = ["total_cve_count"]
            else:
                sort_priority = [sort_by] if isinstance(sort_by, str) else list(sort_by)

            implied_metrics = []
            filter_keys = list(filters.keys())
            for key in filter_keys[:2]:  # Only primary + secondary
                if key == "pr_bucket":
                    implied_metrics.append("mean_pagerank")
                elif key == "tds_bucket":
                    implied_metrics.append("mean_tds")
                elif key == "freshness_bucket":
                    implied_metrics.append("latest_release")

            all_cols = list(dict.fromkeys(core_cols + implied_metrics + (extra_columns or [])))

            if "total_cve_count" not in sort_priority:
                sort_priority.append("total_cve_count")
            df_sorted = df_filtered.sort_values(by=sort_priority, ascending=ascending)
            final_df = df_sorted[all_cols].head(top_n)
            results[name] = final_df

            sort_description = ", ".join(sort_priority).replace("_", " ").title()
            print(f"\n{name} - Top {top_n} artifacts (sorted by {sort_description})")
            if 'latest_release' in final_df.columns:
                final_df['latest_release'] = final_df['latest_release'].dt.strftime("%b %d, %Y")
            display(final_df.reset_index(drop=True))

        return results

   


    def display_table(self, title: str, df: pd.DataFrame):
        styled_html = f"""
        <div style="font-family: Arial, sans-serif; margin-bottom: 20px;">
            <h2 style="color: #4CAF50; border-bottom: 2px solid #4CAF50; padding-bottom: 5px;">{title}</h2>
            {df.to_html(index=False, classes='table table-striped', border=0)}
        </div>
        """
        display(HTML(styled_html))