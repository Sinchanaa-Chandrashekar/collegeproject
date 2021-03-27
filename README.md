                                                                     THEME:VIGILANT CYBER RELIABILITY

INTRODUCTION TO PHISHING.
     Phishing is one of the most commonly used social engineering and cyber attack. Through these attacks the phishers target naïve online users into revealing confidential    information, for using it fraudulently.
     In order to avoid getting phished,
        :- users should have awareness of phishing websites.
        :- have a blacklist of phishing websites which requires the knowledge of website being detected  as phishing.
        :- detect them in their early appearance, using machine learning and deep neural network  algorithms.
     Of	the	above three, the machine learning based	method	is proven to	be	most  effective than the other methods.


PHISHING WEBSITES.
    A phishing website is a common social engineering method that mimics trustful uniform resource locators (URLs) and webpages. The objective of this project is to train machine learning models and deep neural nets on the dataset created to predict phishing websites. Both phishing and benign URLs of websites are gathered to form a dataset and from them required URL and website content-based features are extracted. The performance level of each model is measures and compared.


DATA COLLECTION.
    The set of phishing URLs are collected from opensource service called PhishTank. This service provide a set of phishing URLs in multiple formats like csv, json etc. that gets updated hourly. To download the data: https://www.phishtank.com/developer_info.php. From this dataset, 5000 random phishing URLs are collected to train the ML models.

The legitimate URLs are obatined from the open datasets of the University of New Brunswick, https://www.unb.ca/cic/datasets/url-2016.html. This dataset has a collection of benign, spam, phishing, malware & defacement URLs. Out of all these types, the benign url dataset is considered for this project. From this dataset, 5000 random legitimate URLs are collected to train the ML models.
The above mentioned datasets are uploaded to the 'DataFiles' folder of this repository.


TECHNOLOGY STACK.
    ~ PYTHON -> Machine learning and GUI
    ~ HTML & CSS -> Template for web extensions
    ~ JAVASCRIPT -> Runs web extension.
    
    
APPROACH.
     The steps involved in the completion of this project:
        -> Collect dataset containing phishing and legitimate websites from the open source platforms.
        -> Write a code to extract the required features from the U R L  database.
        -> Analyze and preprocess the dataset by using E D A  techniques.
        -> Divide the dataset into training and testing sets.
        -> Run selected machine learning and deep neural network algorithms like XGBoost classifier.
        -> Write a code for displaying the evaluation result considering accuracy metrics.
        -> Compare the obtained results for trained models and specify which is better.
        
        
FEATURE SELECTION.
    The following category of features are selected:
         ~ Address Bar based Features
         ~ Domain based Features
         ~ H T M L & Javascript based Feature

    Address Bar based Features  considered here are:
           • Domian of U R L
           • Redirection ‘//’ in U R L
           • I P Address in U R L
           • ‘http/https’ in Domain name
           • ‘@’ Symbol in U R L
           • Using U R L Shortening Service
           • Length of U R L
           • Prefix or Suffix "-" in Domain
           • Depth of U R L
           
           
 MACHINE LEARNING MODELS.
       ~ This is a supervised machine learning task. There are two major types of supervised machine learning problems, called classification and regression.
       ~ This data set comes under classification problem, as the input  U R L   is classified as  phishing (1) or legitimate (0). The machine learning models (classification)             considered  to train the dataset in this notebook is:  XGBoost
       ~ The models are evaluated, and the considered metric is accuracy.
                ML MODEL  :  XGBOOST
                TRAIN ACCURACY :  0.868
                TEST ACCURACY   : 0.857
                
                
  END RESULTS.
        From the obtained results of the above models, XGBoost Classifier has highest model performance of 86.8%. So the model is saved to the file        'XGBoostClassifier.pickle.dat'
                




  
  
  

  
 





