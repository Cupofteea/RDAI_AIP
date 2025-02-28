import os 
import spacy
import re
import configparser
import ast
import json
import sys

from langchain.text_splitter import RecursiveCharacterTextSplitter
from unicodedata import category


# ----------------------------------------------------------
# NER + RE Model    
    
class NERModel():

    def __init__(self, model_name):
        path = os.path.dirname(os.path.realpath(__file__))

        #Model path
        self.model_path = os.path.join(path, "nlp_models", model_name, "model-best") #CHANGE PATH ACCORDING TO DIRECTORY

        #Load model 
        self.nlp = spacy.load(self.model_path)

        # Load tokenizer
        self.tokenizer = self.nlp.tokenizer

        # Loading Heuristics
        self.heuristics = configparser.ConfigParser()
        self.heuristics.read(os.path.join(path,'heuristics_labels.ini'))


        self.adversary = ast.literal_eval(self.heuristics.get("Adversary", "List"))
        self.malware = ast.literal_eval(self.heuristics.get("Malware", "List"))
        self.tool = ast.literal_eval(self.heuristics.get("Tool", "List"))
        self.sector = ast.literal_eval(self.heuristics.get("Sector", "List"))
        self.campaign = ast.literal_eval(self.heuristics.get("Campaign", "List"))
        self.region = ast.literal_eval(self.heuristics.get("Region", "List"))
        self.country = ast.literal_eval(self.heuristics.get("Country", "List"))
        self.malwareType = ast.literal_eval(self.heuristics.get("MalwareType", "List"))
        self.fileType = ast.literal_eval(self.heuristics.get("FileType", "List"))
        self.benignWords = ast.literal_eval(self.heuristics.get("BenignWords", "List"))
        
        # Loading MITRE TTPs
        
        with open(os.path.join(path, "mitre_ntram.json"), 'r') as mitre_json:
            self.m_data = json.load(mitre_json)
            
        # Load Entity Labels
        self.entity_labels = ["Adversary: Actor", 
                "Capabilities: Malware", 
                "Capabilities: Tool", 
                "Capabilities: Vulnerability", 
                "Victim: Country", 
                "Victim: Sector", 
                "Victim: Region", 
                "Metadata: Campaign", 
                "Capabilities: Malware Type", 
                "Infra: URL", 
                "Infra: IPv4", 
                "Infra: IPv6", 
                "Infra: MAC Address", 
                "Capabilities: PDB Path", 
                "Capabilities: File", 
                "Capabilities: SHA256 Hash", 
                "Capabilities: SHA1 Hash", 
                "Capabilities: MD5 Hash", 
                "Infra: Email Address",
                "Capabilities: Directories", 
                "Infra: Domain Name",] 
        
        
        self.codepoints = range(sys.maxunicode + 1)
        self.punctuations_all = {c for i in self.codepoints if category(c := chr(i)).startswith("P")}


    def concat_title_and_content(self,title, content, concat_symbol="\n\n"):
        title_content_list = []

        if title and title != "":
            title_content_list.append(title)
        title_content_list.append(content)

        # Concatenate with the concat_symbol
        concat_text = concat_symbol.join(title_content_list)

        return concat_text
    
    def overlap(self,ent1, ent2):
        if ent2[0] >= ent1[0] and ent2[1] <= ent1[1]:
            return True
        elif ent1[0] >= ent2[0] and ent1[1] <= ent2[1]:
            return True
        elif ent2[0] <= ent1[0] and (ent2[0] <= ent1[1] and ent2[1] >= ent1[0]):
            return True
        elif (ent2[0] >= ent1[0] and ent2[0] <= ent1[1]) and ent2[1] >= ent1[1]:
            return True
        return False

    def getEntityIndex(self, text):
        try:
            idx = self.entity_labels.index(text)
        except ValueError:
            idx = len(self.entity_labels)
        return idx
        
    
    def runHeuristicNER(self, text, p_index):       
        output = {}
        entities = set()

        #run heuristics first
        #actor not intrusion_set not threat_actors
        entities.update([(m.start(0), m.end(0), m.group(0), "ACTOR", "Adversary: Actor") for m in re.finditer(r"\b(APT\d+|APT \d+|FIN\d+|TEMP\.[A-Za-z]+)\b", text)])
        entities.update([(m.start(0), m.end(0), m.group(0), "ACTOR", "Adversary: Actor") for m in re.finditer(r"\b(" + "|".join(self.adversary)+ r")\b", text, flags=re.I)])
        #countries
        entities.update([(m.start(0), m.end(0), m.group(0), "COUNTRY", "Victim: Country") for m in re.finditer(r"\b(" + "|".join(self.country)+ r")\b", text, flags=re.I)])
        #sectors
        entities.update([(m.start(0), m.end(0), m.group(0), "SECTOR", "Victim: Sector") for m in re.finditer(r"\b(" + "|".join(self.sector)+ r")\b", text, flags=re.I)]) 
        #malware
        entities.update([(m.start(0), m.end(0), m.group(0), "MALWARE", "Capabilities: Malware") for m in re.finditer(r"\b(" + "|".join(self.malware)+ r")\b", text, flags=re.I)]) 
        #tools
        entities.update([(m.start(0), m.end(0), m.group(0), "TOOL", "Capabilities: Tool") for m in re.finditer(r"\b(" + "|".join(self.tool) + r")\b", text, flags=re.I)]) 
        #tools
        entities.update([(m.start(0), m.end(0), m.group(0), "MALWARETYPE", "Capabilities: Malware Type") for m in re.finditer(r"\b(" + "|".join(self.malwareType) + r")\b", text, flags=re.I)]) 
        #vuln
        entities.update([(m.start(0), m.end(0), m.group(0), "VULN", "Capabilities: Vulnerability") for m in re.finditer(r"\b(CVE-\d+-\d+)\b", text)]) #CVE-\d{4}-\d{4,6}

        #indicator_MD5_hash
        entities.update([(m.start(0), m.end(0), m.group(0), "INDICATOR", "Capabilities: MD5 Hash") for m in re.finditer(r"\b([a-fA-F\d]{32})\b", text)])
        #indicator_SHA1_hash
        entities.update([(m.start(0), m.end(0), m.group(0), "INDICATOR", "Capabilities: SHA1 Hash") for m in re.finditer(r"\b([a-fA-F\d]{40})\b", text)])
        #indicator_SHA256_hash
        entities.update([(m.start(0), m.end(0), m.group(0), "INDICATOR", "Capabilities: SHA256 Hash") for m in re.finditer(r"\b([a-fA-F\d]{64})\b", text)])
    

        # indicator_url email domain file and directory
        urlentities = set()
        urlentities2 = set()
        url_pattern = r"\b(http(s)?:\/\/.)?(hxxp(s)?:\/\/.)?(www\.)?[-a-zA-Z0-9@:%._\+~#=]{2,256}(?:\[\.\]|\.)[a-zA-Z0-9]{2,6}([-a-zA-Z0-9@:%_\+.~#?&//=(?:\[\.\]|\.)]*)\b"
        urlentities.update([(m.start(0), m.end(0), m.group(0), "INDICATOR", "Indicator") for m in re.finditer(url_pattern, text)])
        directory_pattern = r"\b[a-zA-Z]:[^ :\*\?\"<>]*\.?[a-z]{0,6}\b"
        urlentities.update([(m.start(0), m.end(0), m.group(0), "INDICATOR", "Indicator") for m in re.finditer(directory_pattern, text, flags=re.I)])
        file_pattern = r"\b[^\*\?\"<>|]*\.(" + "|".join(self.fileType) + r")\b"
        # print(file_pattern)
        for ent in sorted(urlentities):
            the_str = ent[2]
            temp = list(ent)
            if re.match(r"\b([\w(?:\[\.\]|\.)-]+@[\w(?:\[\.\]|\.)-]+)\b", the_str, flags=re.I):  #match email address
                temp[4] = "Infra: Email Address"
                urlentities2.add(tuple(temp))
            elif re.match(r"\b(http|https|hxxp|hxxps|www).*\b", the_str, flags=re.I): #match URL
                temp[4] = "Infra: URL"
                urlentities2.add(tuple(temp))
            elif re.match(r"\b[^ \*\?\"<>|]*\.(pdb)\b", the_str, flags=re.I): #match PDB file
                temp[4] = "Capabilities: PDB Path"
                urlentities2.add(tuple(temp))
            elif re.match(file_pattern, the_str, flags=re.I): #match other common files
                temp[4] = "Capabilities: File"
                urlentities2.add(tuple(temp))
            elif re.match(r"\b[a-zA-Z]:[^ :\*\?\"<>|\.]*\b", the_str, flags=re.I): #match directory
                temp[4] = "Capabilities: Directories"
                urlentities2.add(tuple(temp))
            elif re.match(r"\b(([a-z])([0-9]{1,2})-{0,3})?((?=[a-z0-9-]{1,63}(?:\[\.\]|\.))(xn--)?[a-z0-9]+(-[a-z0-9]+)*(?:\[\.\]|\.))+[a-z]{2,63}\b", the_str, flags=re.I): #match domain names
                temp[4] = "Infra: Domain Name"
                urlentities2.add(tuple(temp))
            else:
                temp[4] = "Capabilities: File"

        entities.update(urlentities2)
        #indicator_ipv4
        entities.update([(m.start(0), m.end(0), m.group(0), "INDICATOR", "Infra: IPv4") for m in re.finditer(r"\b(\d+(?:\[\.\]|\.)\d+(?:\[\.\]|\.)\d+(?:\[\.\]|\.)\d+(:\d+)?)\b", text)])
        #indicator_ipv6
        entities.update([(m.start(0), m.end(0), m.group(0), "INDICATOR", "Infra: IPv6") for m in re.finditer(r"\b(([a-fA-F\d]{4}:){7}[a-fA-F\d]{4})\b", text)])
        #indicator_mac_address
        entities.update([(m.start(0), m.end(0), m.group(0), "INDICATOR", "Infra: MAC Address") for m in re.finditer(r"\b(([a-fA-F\d]{2}:){5}[a-fA-F\d]{2})\b", text)])


        c_ent1 = sorted([(m.start(0), m.end(0), m.group(0), "CAMPAIGN", "Metadata: Campaign") for m in re.finditer(r"\b(" + "|".join(self.campaign)+ r")\b", text, flags=re.I)])
        c_ent2 = sorted([(m.start(0), m.end(0), m.group(0), "CAMPAIGN", "Metadata: Campaign") for m in re.finditer(r"\b(Operation [A-Z][A-Za-z1-9-]+( [A-Z][a-z1-9-]+)?)\b", text)])
        #regions
        entities.update([(m.start(0), m.end(0), m.group(0), "REGION", "Victim: Region") for m in re.finditer(r"\b(" + "|".join(self.region)+ r")\b", text, flags=re.I)])

        # mitre TTPs
        for tactic in self.m_data["mitre_tactics"]:
            for t in tactic["techniques"]:
                sentenceList = t["tram_examples"]
                technique = "Capabilities: " + tactic["tactic_name"]+" - " + t["technique_name"] + " (" + t["technique_id"] + ")"
                entities.update([(m.start(0), m.end(0), m.group(0), "MITRE_TTP", technique) for m in re.finditer(r"\b(" + "|".join(sentenceList)+ r")\b", text, flags=re.I)])

        #for campaign entities
        if len(c_ent1) == 0:
            entities.update(c_ent2)
        else:
            for e2 in c_ent2:
                overlap_campaign = False
                for e1 in c_ent1:
                    if self.overlap(e1, e2):
                        overlap_campaign = True
                        break
                if overlap_campaign:
                    entities.add(e1)    #e1 comes from list, more priority
                else:
                    entities.add(e2)    #if no overlap then add e2 

        # then add in entities from spacy
        doc = self.nlp(text) # runs the custom spacy NER model
        for ent in doc.ents:
            if ent.text in self.benignWords: # if text identified is found in benignword list, ignore. this tends to happen due to difference in wording style across reports.
                continue
            elif ".site" in ent.text or ".website" in ent.text or len(ent.text.split()) >= 10: # entities ends with ".site", ".website", or are very long are wrongly identified.
                continue
            else:
                if ent.label_ == "a_actor":
                    if ".dll" not in ent.text:
                        entities.update([(ent.start_char, ent.end_char, ent.text, ent.label_.upper(), "Adversary: Actor")])
                elif ent.label_ == "c_malware":
                    if ".dll" not in ent.text:
                        entities.update([(ent.start_char, ent.end_char, ent.text, ent.label_.upper(), "Capabilities: Malware")])
                elif ent.label_ == "c_malwaretype":
                    if ".dll" not in ent.text:
                        entities.update([(ent.start_char, ent.end_char, ent.text, ent.label_.upper(), "Capabilities: Malware Type")])
                elif ent.label_ == "c_tool":
                    entities.update([(ent.start_char, ent.end_char, ent.text, ent.label_.upper(), "Capabilities: Tool")])
                elif ent.label_ == "v_name":
                    entities.update([(ent.start_char, ent.end_char, ent.text, ent.label_.upper(), "Victim: Name")])
                elif ent.label_ == "v_country":
                    if str(ent.text).lower() in (country_name.lower() for country_name in self.country):
                        entities.update([(ent.start_char, ent.end_char, ent.text, ent.label_.upper(), "Victim: Country")])
                elif ent.label_ == "v_region":
                    entities.update([(ent.start_char, ent.end_char, ent.text, ent.label_.upper(), "Victim: Region")])
                elif ent.label_ == "v_sector":
                    entities.update([(ent.start_char, ent.end_char, ent.text, ent.label_.upper(), "Victim: Sector")])
                elif ent.label_ == "i_name":
                    entities.update([(ent.start_char, ent.end_char, ent.text, ent.label_.upper(), "Infra: Domain Name")])
                elif ent.label_ == "a_country":
                    if str(ent.text).lower() in (country_name.lower() for country_name in self.country):
                        entities.update([(ent.start_char, ent.end_char, ent.text, ent.label_.upper(), "Adversary: Country")])

        output["spacyNER"] = []
        keywords = {}

        entities_sorted = sorted(entities) #sort the tuple by start_char (index 0)

        entities_clean = []
        #remove overlapping entities
        for e2 in entities_sorted:
            if entities_clean:
                e1 = entities_clean[-1]
                if self.overlap(e1, e2):
                    e1_labelidx = self.getEntityIndex(e1[4])
                    e2_labelidx = self.getEntityIndex(e2[4])
                    if e1_labelidx > e2_labelidx:   # using labels to define priority
                        entities_clean.pop()        # remove the last entity inserted
                        entities_clean.append(e2)   # insert the prioritized entity
                else:
                    entities_clean.append(e2)
            else:
                entities_clean.append(e2)

        # check to ensure that text is not just a single punctuation. it can occur when using spacy NER.
        entities_clean = [e for e in entities_clean if e[2] not in self.punctuations_all]

        for e in entities_clean:
            if e[2] not in keywords:
                count = 0
                keywords[e[2]] = count
            else:
                count = keywords[e[2]] + 1
                keywords[e[2]] = count
            output["spacyNER"].append({"start_char": e[0], "end_char": e[1], "text": e[2], "label": e[3], "pretty_label": e[4], "occurrence": count, "tag_index": p_index})
        
        output["spacyNER"] = sorted(output["spacyNER"], key = lambda i: (i['start_char'])) 
        


        return output
    
    
    def getEntities(self, title, content):
        # Concatenate title and content
        text = self.concat_title_and_content(title, content)
        
        # Split text into new line chunks
        text_chunks = text.split("\n")
                
        # Run NER on each chunk
        total_entities = []
        i = 0
        for chunk in text_chunks:
            if chunk:
                
                entities = self.runHeuristicNER(chunk, i )["spacyNER"]
                                
                # processed_output = {
                #     "chunk": chunk, 
                #     "spacyNER": entities,
                #     "paragraph_index": i}
                
                total_entities += entities
                
                i += 1
        return total_entities
    
    
    
    
    
    
    
    
    
    
    
    
    