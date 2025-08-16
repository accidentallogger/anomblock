#!/usr/bin/env python3
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import numpy as np
import os

CSV_IN = '/tmp/insdn_features.csv'
OUT_DIR = './preprocessed'
os.makedirs(OUT_DIR, exist_ok=True)

df = pd.read_csv(CSV_IN)
# Drop non-numeric or identifier columns
drop_cols = ['FlowID','SrcIP','DstIP','StartTime']
for c in drop_cols:
    if c in df.columns:
        df = df.drop(columns=[c])
# fill NaN
df = df.fillna(0)
# label
if 'Label' in df.columns:
    y = df['Label'].astype(int)
    X = df.drop(columns=['Label'])
else:
    y = pd.Series(np.zeros(len(df)))
    X = df

# only keep numeric features
X = X.select_dtypes(include=[float,int])
scaler = StandardScaler()
Xs = scaler.fit_transform(X)
X_train, X_test, y_train, y_test = train_test_split(Xs, y.values, test_size=0.2, random_state=42)
pd.DataFrame(X_train).to_csv(os.path.join(OUT_DIR,'X_train.csv'), index=False)
pd.DataFrame(X_test).to_csv(os.path.join(OUT_DIR,'X_test.csv'), index=False)
pd.DataFrame(y_train).to_csv(os.path.join(OUT_DIR,'y_train.csv'), index=False)
pd.DataFrame(y_test).to_csv(os.path.join(OUT_DIR,'y_test.csv'), index=False)
print("Saved preprocessed train/test in", OUT_DIR)
