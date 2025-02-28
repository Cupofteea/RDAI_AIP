import os 
import spacy



class ClassifierModel():

    def __init__(self, model_name, thres):
        path = os.path.dirname(os.path.realpath(__file__))

        #Model path
        self.model_path = os.path.join(path, "nlp_models", model_name, "model-last") #CHANGE PATH ACCORDING TO DIRECTORY

        #Load model 
        self.nlp = spacy.load(self.model_path)

        # Load tokenizer
        self.tokenizer = self.nlp.tokenizer
        
        self.thres = thres

    def change_thres(self, new_thres):
        """
        Change the threshold value. Used for standardising tags
        Input: new_thres (float: 0-1)
        """
        self.thres = new_thres

    def get_raw_labels(self, txt):    
        """
        Get the confidence probability for each label.
        Input: txt (String)
        Output: Dict {"Label": float (0-1)}
        """         
        doc = self.nlp(txt)
        return doc.cats
    
    def concat_title_and_content(self,title, content, concat_symbol=" "):
        title_content_list = []

        if title and title != "":
            title_content_list.append(title)
        title_content_list.append(content)

        # Concatenate with the concat_symbol
        concat_text = concat_symbol.join(title_content_list)

        return concat_text
    
    def standardize_tags(self, raw_labels):
        """
        Converts confidence probability into binary
        Input: Dictionary {"Label": float (0-1)}
        Output: Dictionary {"Label": int (binary)}
        """
        tags = raw_labels
        for k in tags:
            if tags[k] >= self.thres: 
                tags[k] = 1
            else:
                tags[k] = 0
        return tags
    
# ----------------------------------------------------------
# Report Classification Model

class ReportClassifierModel(ClassifierModel):
    
    #Do i need one more field for type of model??? eg NER, Text classification
    def __init__(self, model_name, thres):
        super().__init__(model_name,thres)
        
    def get_final_labels(self, title, content):
        """
        Returns a list of labels for a given txt. 
        Input: txt (String)
        Output: List of Strings
        """

        # Concatenate title and content
        txt = super().concat_title_and_content(title, content)

        # Use ML model to get some labels
        # We blacklist some labels because model performance isn't fantastic
        blacklisted_ml_labels = ["CYBER WARFARE", "DEFACEMENT", "TARGETED CLOUD", "TARGETED IOT", "TARGETED OT", "TARGETED VPN", "ZERO DAY VULN"]
        raw_labels = super().get_raw_labels(txt)
        standardised_labels = super().standardize_tags(raw_labels)
        ml_model_labels = [label for label in standardised_labels if standardised_labels[label] == 1 and label not in blacklisted_ml_labels]

        return ml_model_labels  
    

