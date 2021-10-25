"""
Static Analysis
"""

import pickle
import os 
import pefile
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from sklearn.preprocessing import OrdinalEncoder, MinMaxScaler
from scipy.cluster.hierarchy import fcluster, linkage
from scipy.cluster.hierarchy import dendrogram


# pip install pefile is needed
# It combines 40 malware's pefile.dump_dict().
with open("/content/pef_dumpdict_40.pickle", 'rb') as fd:
    pef_dumpdicts = pickle.load(fd)

# The id of the 40 malwares
for key in pef_dumpdicts.keys():
    print(key)


# Here you can output the dll and windows api used by a pe file
# You may print dump_dict['Imported symbols'] first
# and try to locate the info you want to retrieve.

api_dict = dict()
for records in first_dict['Imported symbols']:
    for record in records:
        if 'Name' in record:
            if isinstance(record['Name'], bytes):
                dll = record['DLL'].decode("ascii")
                name = record['Name'].decode("ascii")
                if dll not in api_dict:
                    api_dict[dll] = set()
                api_dict[dll].add(name)

for dll in api_dict:
    print(dll)
    print("", api_dict[dll])

 
# Try to build a feature table for these 40 malwares.
api_set = set()
for key in pef_dumpdicts.keys():  # iter 40 malwares
    pef_dump_dict = pef_dumpdicts[key]
    for records in pef_dump_dict['Imported symbols']:
        for record in records:
            if 'Name' in record:
                if isinstance(record['Name'], bytes):
                    name = record['Name'].decode("ascii")
                    api_set.add(name)

api_list = list(api_set)
mw_name_list = list(pef_dumpdicts.keys())
name_list = [key for key in pef_dumpdicts.keys()]
    
dic = {
    'SHA1_1': [],
    'SHA1_2': [],
    'SHA1_3': [],
    'MISC_V1': [],
    'MISC_V2': [],
    'MISC_V3': [],
    'SizeOfRawData_1': [],
    'SizeOfRawData_2': [],
    'SizeOfRawData_3': [],
    'Misc_PhysicalAddress_1': [],
    'Misc_PhysicalAddress_2': [],
    'Misc_PhysicalAddress_3': []
}


for key in pef_dumpdicts.keys():  # iter 40 malware
    pef_dump_dict = pef_dumpdicts[key]
    for record in pef_dump_dict['PE Sections']:
        ind = pef_dump_dict['PE Sections'].index(record)+1
        if ind < 4:
            dic['SHA1_%s' % str(ind)].append(record['SHA1'])
            dic['MISC_V%s' % str(ind)].append(record['Misc']['Value'])
            dic['SizeOfRawData_%s' % str(ind)].append(record['SizeOfRawData']['Value'])
            dic['Misc_PhysicalAddress_%s' % str(ind)].append(record['Misc_PhysicalAddress']['Value'])

df = pd.DataFrame(dic)
df.index = name_list

"""## Data Preprocessing
- Change categorical data to numerical data by Ordinal Encoder
- Standardize numerical data by MinMaxScaler
"""

enc = OrdinalEncoder()
scaler = MinMaxScaler()
df["SHA1_1"] = enc.fit_transform(df[['SHA1_1']]).astype(int)
df["SHA1_2"] = enc.fit_transform(df[['SHA1_2']]).astype(int)
df["SHA1_3"] = enc.fit_transform(df[['SHA1_3']]).astype(int)

df[['MISC_V1', 'MISC_V2', 'MISC_V3', 'SizeOfRawData_2', 'SizeOfRawData_3', 'Misc_PhysicalAddress_1',
    'Misc_PhysicalAddress_2', 'Misc_PhysicalAddress_3']] = scaler.fit_transform(df[['MISC_V1', 'MISC_V2', 'MISC_V3',
                                                                                    'SizeOfRawData_2',
                                                                                    'SizeOfRawData_3',
                                                                                    'Misc_PhysicalAddress_1',
                                                                                    'Misc_PhysicalAddress_2',
                                                                                    'Misc_PhysicalAddress_3']])

"""## Clustering
- Hierarchical clustering to cluster 4 malware familys
"""

distance_matrix = linkage(df, method='ward', metric='euclidean')
dn = dendrogram(distance_matrix, color_threshold=10)
plt.show()
