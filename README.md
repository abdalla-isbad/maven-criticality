# Maven Central Criticality Analysis

This project performs a criticality analysis of Maven Central packages using PageRank, Transitive Dependency Size (TDS), and Freshness metrics.  


## Features

- **PageRank Analysis**: Measures package importance in the dependency network
- **Transitive Dependency Size (TDS)**: Analyzes dependency complexity
- **Freshness Metrics**: Evaluates package maintenance status
- **CVE Integration**: Security vulnerability analysis
- **Pfeiffer's Work Replication**: Reproduces key findings from academic research from https://ieeexplore.ieee.org/document/9463111/

## Quick Start

### Prerequisites

- Python 3.8 or higher
- pip package manager

### Installation

1. **Clone the repository**:

   ```bash
   git clone https://github.com/abdalla-isbad/maven-criticality.git
   cd maven-criticality
   ```

2. **Create and activate a virtual environment**:

   ```bash
   # Windows
   python -m venv venv
   venv\Scripts\activate

   # macOS/Linux
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install dependencies**:

   ```bash
   pip install -r requirements.txt
   ```

4. **Launch Jupyter**:

   ```bash
   jupyter notebook
   ```

5. **Open and run the analysis**:
   - Open `maven_central_analysis.ipynb`
   - Run the cells - the large dataset will be automatically downloaded from Zenodo on first use

## Data Sources

- **Main Dataset**: Automatically downloaded from Zenodo (634MB)
- **Supporting Files**: CVE data, dependency information, and truck factor metrics included in repository
- **External Dependencies**: No manual data preparation required

## Project Structure

```
├── maven_central_analysis.ipynb    # Main analysis notebook
├── criticality_helper.py           # Core analysis functions
├── requirements.txt                # Python dependencies
├── source/                         # Data directory
│   ├── csv/                       # CSV data files
│   └── parquet/                   # Parquet data files (main dataset auto-downloaded)
└── README.md                      # This file
```

## Usage

The notebook automatically handles data download and preprocessing. Simply run the cells in order to:

1. Load and preprocess Maven Central data
2. Calculate criticality scores using multiple metrics
3. Generate visualizations and statistical analyses
4. Replicate key findings from academic literature

## System Requirements

- **RAM**: Minimum 10GB (16GB recommended)
- **Storage**: ~2GB free space (including virtual environment and data)
- **Internet**: Required for initial data download from Zenodo


**Package Issues**:

- Ensure you're using Python 3.8+
- Try upgrading pip: `pip install --upgrade pip`

##Neo4j Database Setup
A prebuilt Neo4j database dump of the Release-to-Release graph is provided via Zenodo for fast setup.
You can load it locally using the included Graph/db_setup.py script or OS specific setup files.

##Usage:

# Linux / macOS
python Graph/db_setup.sh

# Windows
Graph\db_setup.exe

# All
python Graph/db_setup.py

This will:

Download the dump from Zenodo

Create a Neo4j container with APOC and GDS plugins

Load the database for immediate use at http://localhost:7474 (default credentials: neo4j/password)

## License

This project is for academic and research purposes.

## Citation
the original dataset was obtained from:
Jaime, Damien et al.
Goblin: A Framework For Enriching And Querying the Maven Central Dependency Graph (https://doi.org/10.1145/3643991.3644879) - 21st International Conference on Mining Software Repositories (MSR'24).

```bibtex
@misc{maven_central_analysis,
  title={Maven Central Criticality Analysis},
  author={Abdalla Babiker},
  year={2024},
  url={https://github.com/abdalla-isbad/maven-criticality}
}
```
