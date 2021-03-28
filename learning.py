import string
import argparse
# import data
import math
from sklearn.linear_model import LogisticRegression
from sklearn.feature_extraction.text import CountVectorizer
from sklearn import preprocessing
import numpy as np
from warnings import simplefilter

simplefilter(action='ignore', category=FutureWarning)


class Learner:

    def __init__(self):
        self.X_train = []
        self.Y_train = []
        self.X_test = []
        self.X_train_counts = []
        self.clf = LogisticRegression()
        self.predicted_labels = []

    def train(self, X_vals, Y_vals):
        for sample in X_vals:
            self.X_train.append(sample)
        for tag in Y_vals:
            self.Y_train.append(tag)

        print("Training model...\n")

        # self. X_train_counts = scaler.fit_transform(X_train_counts)
        self.clf.fit(self.X_train, self.Y_train)  # trains the model using gradient descent

        print("Model successfully trained. \n")

    def test(self, X_vals, Y_vals):
        for sample in X_vals:
            self.X_test.append(sample)

        print("Testing accuracy with labeled dataset. \n")

        self.predicted_labels = self.clf.predict(self.X_test)

        correct = 0
        count = 0
        for i, tag in enumerate(Y_vals):
            if tag == self.predicted_labels[i]:
                correct += 1
            count += 1
        percent = (correct / count) * 100
        print("Model rated with a", percent, "% accuracy rate. \n")


'''
l = Learner()
l.train([ [0,1,2,3], [0,1,3,4], [0,1,2,8] ], ['a', 'b', 'e'] )
l.test([ [0,5,2,3], [4,1,3,4], [0,0,2,8] ], ['a', 'b', 'b'] )
'''
