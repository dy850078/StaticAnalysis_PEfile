# StaticAnalysis_PEfile


## Overview
Using Hierarchical Clustering to classify malicious PE files into malware family


## Feature selection & Data Frames creation
### Features
- 3 SHA1 in each malware's PE sections 
- 3 Misc Valuse in each malware's PE sections
- 3 Misc_PhysicalAddress Value in each malware's PE sections
- 3 SizeOfRawData in each malware's PE sections

## Data Preprocessing
- Change categorical data to numerical data by Ordinal Encoder
- Standardize numerical data by MinMaxScaler

## Clustering
- Hierarchical clustering to cluster 4 malware familys
