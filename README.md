# Open Source Supply Chains: The Ripple Effect

> A structural risk-analysis prototype that shows how the compromise of one open-source dependency can ripple through an entire software ecosystem.

## The Problem

Modern software depends on large networks of open-source packages. Traditional vulnerability scanners generally assess each package in isolation—for example, by displaying its CVSS score.

This misses an important part of supply-chain risk: **Dependency Structure**

A severe vulnerability in a package with no dependents may have limited ecosystem impact. In contrast, a small foundational utility may be used indirectly by most of the ecosystem, making it a critical single point of failure—even when it has no known vulnerability.

The xz-utils incident demonstrated this limitation: before the backdoor was discovered, a vulnerability-only scanner would not have identified the package as an active risk.

## Our Solution

**The Ripple Effect** analyzes the full dependency graph rather than evaluating packages independently.

It produces two complementary outputs:

1. **Active Risk List:**  
   Packages with known vulnerabilities, ranked using both vulnerability severity and ecosystem blast radius.

2. **Structural Watchlist:**  
   Packages with no known vulnerability but a large dependency blast radius. These packages deserve proactive monitoring and hardening.

The prototype also traces propagation paths, runs probabilistic compromise simulations, and recommends which vulnerabilities should be addressed first.

## Why It Is Different

Most scanners answer:

> “How severe is this vulnerability?”

The Ripple Effect also asks:

> “If this package is compromised, how much of the ecosystem can it reach?”

This allows the system to identify both:

- **Known risks** that require immediate patching
- **Unknown structural risks** that should be monitored before an incident occurs

## Core Features

### Dependency Graph

Displays packages as a directed dependency network.

- Arrows point from a package to its dependency
- Node size represents potential blast radius
- Red nodes indicate known vulnerabilities
- Yellow nodes indicate structural watchlist packages
- Green nodes indicate packages without a current warning
- The selected compromise point is highlighted
- Propagation paths are displayed in orange

### Active Risk Ranking

Known vulnerabilities are ranked using:

```text
Risk Score = CVSS Score × Impact Score
```

Where:

```text
Impact Score = Number of packages affected (if compromised) ÷ Total number of other packages
```

This prevents a high CVSS score with very limited reach from automatically outranking a vulnerability with greater ecosystem-wide impact.

### Structural Watchlist

The Structural Watchlist identifies packages that:

- Have no known active vulnerability
- Exceed the configured impact-score threshold
- Represent high-value targets or single points of failure

This is the prototype’s main proactive capability.

### Propagation Path Tracing

For every affected package, the application calculates the shortest dependency chain through which a compromise could propagate.

Example:

```text
http-client → auth-service → web-app
```

This explains not only **what** is affected, but also **how** the compromise reaches it.

### Monte Carlo Simulation

A compromise may not cross every dependency edge because of:

- Pinned dependency versions
- Lockfiles
- Security review
- Isolation controls
- Different deployment configurations

The application therefore runs repeated probabilistic simulations using a configurable transmission probability.

It compares:

- Deterministic worst-case blast radius
- Average simulated impact
- Minimum and maximum observed impact
- Distribution of outcomes across simulation runs

### Mitigation Priority Ranking

The prototype estimates how much of the measured ecosystem risk can be removed by patching each vulnerable package.

This helps teams prioritize limited engineering time based on overall risk reduction instead of raw severity alone.

## How It Works

The prototype models the ecosystem as a directed acyclic graph using NetworkX.

```text
Package A → Package B
```

means:

```text
Package A depends on Package B
```

If Package B is compromised, the compromise may propagate in the reverse direction toward Package A and its downstream dependents.

### Processing Flow

1. Build the dependency graph
2. Attach known vulnerability information
3. Calculate the downstream blast radius of every package
4. Calculate impact and active-risk scores
5. Generate the Structural Watchlist
6. Trace propagation paths
7. Run Monte Carlo simulations
8. Rank mitigation priorities
9. Display the results through Streamlit and Pyvis

## Technology Stack

- **Python 3**
- **Streamlit** — interactive application interface
- **NetworkX** — graph construction and analysis
- **Pyvis** — dependency-network visualization
- **Pandas** — result tables and simulation summaries

## Running the Prototype

### 1. Clone the repository

```bash
git clone https://github.com/Null-Pointerz/Open-Source-Supply-Chain-Risk-Analysis/
#Use cd to select the folder where you downloaded the file.
```

### 2. Install dependencies

```bash
pip install streamlit networkx pandas pyvis
```

### 3. Start the application

```bash
streamlit run app.py
```

Streamlit will display the local application URL in the terminal.

## Using the Application

1. Select a simulated compromise point from the sidebar
2. Set the transmission probability
3. Choose the number of Monte Carlo runs
4. Set a random seed for reproducible results
5. Select a downstream target to view its propagation path
6. Review the Active Risk and Structural Watchlist tables
7. Inspect the reasoning provided for each ranking
8. Review the simulation distribution and mitigation priorities

## Prototype Scope

This Round 1 prototype uses a hardcoded sample ecosystem to demonstrate the risk model clearly and reproducibly.

It currently does not:

- Scan a real repository
- Parse package lockfiles
- Retrieve live CVE information
- Model package versions or deployment environments
- Account for exploitability controls beyond transmission probability
- Replace a production software-composition-analysis platform

Risk scores are comparative decision-support indicators, not guarantees that a compromise will occur.

## Project Structure

```text
.
├── app.py
├── README.md
└── requirements.txt
```

## Requirements File

A minimal `requirements.txt` can contain:

```text
streamlit
networkx
pandas
pyvis
```

## Prototype Status

This repository contains a functional Round 1 proof of concept. It is intended to demonstrate the proposed solution, its key algorithms, user experience, and potential for further development.

## Demo

- **Live prototype:** <ADD_PUBLIC_DEPLOYMENT_LINK>
- **Video demonstration:** <ADD_PUBLIC_VIDEO_LINK>

## Team

- Saharsh Kothapalli
- Praneeth Dharmapuri
- Madhav Sunil
- Gaurav Satish
