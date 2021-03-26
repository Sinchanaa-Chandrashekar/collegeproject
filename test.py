import pickle

loaded_model = pickle.load(open("XGBoostClassifier.pickle.dat", "rb"))
print(loaded_model)