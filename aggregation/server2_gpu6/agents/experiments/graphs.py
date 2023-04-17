import pandas as pd
import matplotlib.pyplot as plt

df1 = pd.read_csv("local_training.csv")
df2 = pd.read_csv("worker-0-stats.csv")
df3 = pd.read_csv("worker-1-stats.csv")


df1.loc[:, "val_loss":].plot(title="Local training")


df2.loc[:, "val_loss":].plot()


df3.loc[:, "val_loss":].plot()
plt.show()
