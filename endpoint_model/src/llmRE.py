import llmUtils
import logging
import os
import yaml

from helper import create_logger


class LLMRE():
    
    def __init__(self):
        # Get configuration
        self.config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        self.cfg = yaml.load(open(self.config_file_path), Loader=yaml.FullLoader)

        # Logging
        log_file_path = os.path.dirname(os.path.abspath(__file__)) + "/logs/llm_re.log"
        logging_format = '%(asctime)s - %(message)s'
        self.logger = create_logger('LLM_RE', log_file_path, logging_format, logging.INFO)
        
        # AWS credentials
        self.aws_access_key_id = self.cfg["aws_creds"]["access_key_id"]
        self.aws_secret_access_key = self.cfg["aws_creds"]["secret_access_key"]
        
        # Models
        self.llm_re_model = self.cfg["aws_models"]["llm_re_model"]
        self.aws_region = self.cfg["aws_models"]["region"]
        

    def construct_RE_prompt(self, article, entities):
        """
        Constructs a prompt requesting for the extraction of relationships from an article to be sent to the LLM 
        
        :param article: the article from which relationships are to be extracted from
        :type article: str
        :param entities: a json str containing a list of entities that were previously extracted
        :type entities: str
        :returns: a list of messages in the specified format to be sent to the LLM
        :rtype: list
        """
        first_user_msg = """
        You are a relationship extraction model which identifies relationships between named entities accurately.
        You will be provided with a cybersecurity article. The article will be delimited by $$$ characters.
        You will also be provided with a list of named entities in JSON format, delimited by *** characters.
        With reference to this list of named entities, extract relationships between these entities based on the context of the article provided.
        You will be given a list of relationships, delimited by ''' characters.
        The relationships that you extract must strictly follow the types of relationships as described in the list of relationships.
        
        The list of relationships specifies each type of relationship a particular type of source entity can have with a particular type of target entity.
        Each relationship must involve only 1 source entity and 1 target entity.
        Relationships are specified in this format: [source-entity-type] [relationship] [target-entity-type].
        For entities whose "indicator_type" value is not "NA", treat those entities as both an indicator entity and the specific type of indicator entity as specified. 
        
        '''
        [campaign] [attributed-to] [intrusion-set]
        [campaign] [compromises] [infrastructure]
        [campaign] [originates-from] [location]
        [campaign] [targets] [identity]
        [campaign] [targets] [location]
        [campaign] [targets] [vulnerability]
        [campaign] [uses] [infrastructure]
        [campaign] [uses] [malware]
        [campaign] [uses] [tool]

        [identity] [located-at] [location]

        [indicator] [indicates] [campaign]
        [indicator] [indicates] [infrastructure]
        [indicator] [indicates] [intrusion-set]
        [indicator] [indicates] [malware]
        [indicator] [indicates] [tool]

        [infrastructure] [communicates-with] [infrastructure]
        [infrastructure] [communicates-with] [ipv4-addr]
        [infrastructure] [communicates-with] [ipv6-addr]
        [infrastructure] [communicates-with] [domain-name]
        [infrastructure] [communicates-with] [url]
        [infrastructure] [consists-of] [infrastructure]
        [infrastructure] [consists-of] [ipv4-addr]
        [infrastructure] [consists-of] [ipv6-addr]
        [infrastructure] [consists-of] [domain-name]
        [infrastructure] [consists-of] [url]
        [infrastructure] [consists-of] [directory]
        [infrastructure] [consists-of] [file]
        [infrastructure] [consists-of] [mac-addr]
        [infrastructure] [consists-of] [email-addr]
        [infrastructure] [controls] [infrastructure]
        [infrastructure] [controls] [malware]
        [infrastructure] [delivers] [malware]
        [infrastructure] [has] [vulnerability]
        [infrastructure] [hosts] [tool]
        [infrastructure] [hosts] [malware]
        [infrastructure] [located-at] [location]
        [infrastructure] [uses] [infrastructure]

        [intrusion-set] [related-to] [intrusion-set]
        [intrusion-set] [compromises] [infrastructure]
        [intrusion-set] [hosts] [infrastructure]
        [intrusion-set] [owns] [infrastructure]
        [intrusion-set] [originates-from] [location]
        [intrusion-set] [targets] [identity]
        [intrusion-set] [targets] [location]
        [intrusion-set] [targets] [vulnerability]
        [intrusion-set] [uses] [infrastructure]
        [intrusion-set] [uses] [malware]
        [intrusion-set] [uses] [tool]
        [intrusion-set] [uses] [domain-name]

        [malware] [authored-by] [intrusion-set]
        [malware] [beacons-to] [infrastructure]
        [malware] [exfiltrate-to] [infrastructure]
        [malware] [communicates-with] [ipv4-addr]
        [malware] [communicates-with] [ipv6-addr]
        [malware] [communicates-with] [domain-name]
        [malware] [communicates-with] [url]
        [malware] [controls] [malware]
        [malware] [downloads] [malware]
        [malware] [downloads] [tool]
        [malware] [downloads] [file]
        [malware] [drops] [malware]
        [malware] [drops] [tool]
        [malware] [drops] [file]
        [malware] [exploits] [vulnerability]
        [malware] [originates-from] [location]
        [malware] [targets] [identity]
        [malware] [targets] [infrastructure]
        [malware] [targets] [location]
        [malware] [targets] [vulnerability]
        [malware] [targets] [tool]
        [malware] [uses] [infrastructure]
        [malware] [uses] [malware]
        [malware] [uses] [tool]
        [malware] [variant-of] [malware]

        [tool] [delivers] [malware]
        [tool] [drops] [malware]
        [tool] [has] [vulnerability]
        [tool] [targets] [identity]
        [tool] [targets] [infrastructure]
        [tool] [targets] [location]
        [tool] [targets] [vulnerability]
        [tool] [uses] [infrastructure]
        '''

        For each identified relationship, extract the following information, delimited by ### characters, then output them in JSON format. 

        ###
        "source" : the identified source entity
        "source_pretty_label" : the given pretty_label to the source entity
        "target" : the identified target entity
        "target_pretty_label" : the given pretty_label to the target entity
        "relationship" : the identified relationship including the types of source and target entities
        ###
        
        Return your response as a JSON string without the JSON markdown.
        
        
        $$$
        A ransomware attack that hit pathology services provider Synnovis on Monday and impacted several major NHS hospitals in London has now been linked to the Qilin ransomware operation. 
        Ciaran Martin, the inaugural CEO of the UK's National Cyber Security Centre (NCSC), said today that the Qilin gang is likely responsible for the incident.
        The attack has resulted in Synnovis being locked out of its systems and is causing ongoing service disruptions at Guy's and St Thomas' NHS Foundation Trust, King's College Hospital NHS Foundation Trust, and various primary care providers across south east London.
        $$$
        
        ***
        {
            "entities": [
                {
                    "pretty_label": "Capabilities: Malware Type",
                    "entity_name": "ransomware",
                    "entity_type": "malware",
                    "indicator_type": "NA"
                },
                {
                    "pretty_label": "Victim: Name",
                    "entity_name": "Synnovis",
                    "entity_type": "identity",
                    "indicator_type": "NA"
                },
                {
                    "pretty_label": "Victim: Region",
                    "entity_name": "London",
                    "entity_type": "location",
                    "indicator_type": "NA"
                },
                {
                    "pretty_label": "Adversary: Actor",
                    "entity_name": "Qilin",
                    "entity_type": "intrusion-set",
                    "indicator_type": "NA"
                },
                {
                    "pretty_label": "Victim: Name",
                    "entity_name": "Guy's and St Thomas' NHS Foundation Trust",
                    "entity_type": "identity",
                    "indicator_type": "NA"
                },
                {
                    "pretty_label": "Victim: Name",
                    "entity_name": "King's College Hospital NHS Foundation Trust",
                    "entity_type": "identity",
                    "indicator_type": "NA"
                }
            ]
        }
        ***
        """
        
        example_output1 = """
        {
            "relations": [
                {
                    "source": "ransomware",
                    "source_pretty_label": "Capabilities: Malware Type",
                    "target": "Synnovis",
                    "target_pretty_type": "Victim: Name",
                    "relationship": "malware targets identity"
                },
                {
                    "source": "ransomware",
                    "source_pretty_label": "Capabilities: Malware Type",
                    "target": "Guy's and St Thomas' NHS Foundation Trust",
                    "target_pretty_label": "Victim: Name",
                    "relationship": "malware targets identity"
                },
                {
                    "source": "ransomware",
                    "source_pretty_label": "Capabilities: Malware Type",
                    "target": "King's College Hospital NHS Foundation Trust",
                    "target_pretty_label": "Victim: Name",
                    "relationship": "malware targets identity"
                },
                {
                    "source": "Qilin",
                    "source_pretty_label": "Adversary: Actor",
                    "target": "London",
                    "target_pretty_label": "Victim: Region",
                    "relationship": "intrusion-set targets location"
                },
                {
                    "source": "Qilin",
                    "source_pretty_label": "Adversary: Actor",
                    "target": "Synnovis",
                    "target_pretty_label": "Victim: Name",
                    "relationship": "intrusion-set targets identity"
                },
                {
                    "source": "Qilin",
                    "source_pretty_label": "Adversary: Actor",
                    "target": "Guy's and St Thomas' NHS Foundation Trust",
                    "target_pretty_label": "Victim: Name",
                    "relationship": "intrusion-set targets identity"
                },
                {
                    "source": "Qilin",
                    "source_pretty_label": "Adversary: Actor",
                    "target": "King's College Hospital NHS Foundation Trust",
                    "target_pretty_label": "Victim: Name",
                    "relationship": "intrusion-set targets identity"
                }
            ]
        } 
        """
        
        example_input2 = """
        $$$
        The Iranian nation-state actor known as MuddyWater has been observed using a never-before-seen backdoor as part of a recent attack campaign, shifting away from its well-known tactic of deploying legitimate remote monitoring and management (RMM) software for maintaining persistent access.
        That's according to independent findings from cybersecurity firms Check Point and Sekoia, which have codenamed the malware strain BugSleep and MuddyRot.
        MuddyWater is a state-sponsored threat actor that's assessed to be affiliated with Iran's Ministry of Intelligence and Security (MOIS). 
        Cyber attacks mounted by the group have been fairly consistent, leveraging spear-phishing lures in email messages to deliver various RMM tools like Atera Agent and ScreenConnect.
        $$$
        
        ***
        {
            "entities": [
                {
                    "pretty_label": "Adversary: Actor",
                    "entity_name": "MuddyWater",
                    "entity_type": "intrusion-set",
                    "indicator_type": "NA"
                },
                {
                    "pretty_label": "Capabilities: Malware",
                    "entity_name": "BugSleep",
                    "entity_type": "malware",
                    "indicator_type": "NA"
                },
                {
                    "pretty_label": "Capabilities: Malware",
                    "entity_name": "MuddyRot",
                    "entity_type": "malware",
                    "indicator_type": "NA"
                },
                {
                    "pretty_label": "Victim: Country",
                    "entity_name": "Iran",
                    "entity_type": "location",
                    "indicator_type": "NA"
                },
                {
                    "pretty_label": "Capabilities: Tool",
                    "entity_name": "Atera Agent",
                    "entity_type": "tool",
                    "indicator_type": "NA"
                },
                {
                    "pretty_label": "Capabilities: Tool",
                    "entity_name": "ScreenConnect",
                    "entity_type": "tool",
                    "indicator_type": "NA"
                }
            ]
        }
        ***
        """
        
        example_output2 = """
        {
            "relations": [
                {
                    "source": "MuddyWater",
                    "source_pretty_label": "Adversary: Actor",
                    "target": "BugSleep",
                    "target_pretty_label": "Capabilities: Malware",
                    "relationship": "intrusion-set uses malware"
                },
                {
                    "source": "MuddyWater",
                    "source_pretty_label": "Adversary: Actor",
                    "target": "MuddyRot",
                    "target_pretty_label": "Capabilities: Malware",
                    "relationship": "intrusion-set uses malware"
                },
                {
                    "source": "MuddyWater",
                    "source_pretty_label": "Adversary: Actor",
                    "target": "Iran",
                    "target_pretty_label": "Victim: Country",
                    "relationship": "intrusion-set originates-from location"
                },
                {
                    "source": "MuddyWater",
                    "source_pretty_label": "Adversary: Actor",
                    "target": "Atera Agent",
                    "target_pretty_label": "Capabilities: Tool",
                    "relationship": "intrusion-set uses tool"
                },
                {
                    "source": "MuddyWater",
                    "source_pretty_label": "Adversary: Actor",
                    "target": "ScreenConnect",
                    "target_pretty_label": "Capabilities: Tool",
                    "relationship": "intrusion-set uses tool"
                }
            ]
        }
        """

        article_delimiter = "$$$"
        entities_delimiter = "***"
        messages = [{"role": "user", "content": [{"text": first_user_msg}]},
                    {"role": "assistant", "content": [{"text": example_output1}]},
                    {"role": "user", "content": [{"text": example_input2}]},
                    {"role": "assistant", "content": [{"text": example_output2}]},
                    {"role": "user", "content": [{"text": f"{article_delimiter}\n{article}\n{article_delimiter}\n\n{entities_delimiter}\n{entities}\n{entities_delimiter}"}]}]	

        return messages


    def get_relations(self, article, entities, region):
        """
        Sends a prompt to the LLM to get LLM-extracted relationships
        
        :param log: logger object
        :type log: Logger
        :param article: the article from which relationships are to be extracted from
        :type article: str
        :param entities: a json str containing a list of entities that were previously extracted
        :type entities: str
    
        :param region: user-provided aws region
        :type region: str
        :returns: a tuple containing a list of relationships and a dict showing tokens used
        :rtype: tuple(list, dict)
        """
        input_tokens_count = 0
        output_tokens_count = 0
        
        try: 
            prompt = self.construct_RE_prompt(article, entities)
            response = llmUtils.prompt_llm(self.llm_re_model, prompt, self.aws_access_key_id, self.aws_secret_access_key, region)
            if response["stopReason"] == "max_tokens":
                raise Exception("Output for relationship extraction exceeded the model's maximum number of tokens")
            response_text = response["output"]["message"]["content"][0]["text"]
            recognised_relations = llmUtils.remove_unrecog_rs(response_text)
            final_relations = llmUtils.validate_entities_existence(entities, recognised_relations)
            final_relations = llmUtils.validate_entities_types(final_relations)
            input_tokens_count = response["usage"]["inputTokens"]
            output_tokens_count = response["usage"]["outputTokens"]
            self.logger.info(f"Call to {self.llm_re_model} for extraction of relationships from article successful")
        except Exception as e:
            self.logger.info(f"Exception occurred while calling {self.llm_re_model} for extraction of relationships from article")
            raise Exception(e)
            
        # get proper format for total tokens used for relationship extraction
        tokens_used = llmUtils.get_token_count(input_tokens_count, output_tokens_count)
        
        return final_relations, tokens_used


    def run_llm_RE(self, txt, obj, title):
        """
        Processes a given text to extract relations using a Language Learning Model (LLM) and appends the results to the provided object.
        This function extracts entities from the provided object, formats them, and uses them to obtain relations from the text. 
        The relations are then appended to the object under the key 'llm_RE'.
        :param txt: The text to process for relation extraction.
        :type txt: str
        :param obj: The object containing entities and other relevant information.
        :type obj: dict
        :param title: The title of the article or text being processed.
        :type title: str
        :returns: The updated object with the extracted relations appended.
        :rtype: dict

        """
    
        self.logger.info(f"Processing LLM_RE for \"{title}\"")
        try:	
            entities = []
            if "validatedNER" in obj:
                entities = obj["validatedNER"]["entities"]
            else:
                entities = obj["spacyNER"]
            
            
    
            json_entities = llmUtils.get_stix_labels(entities)
        
            
            relations, tokens_used = self.get_relations(txt, json_entities,self.aws_region)
            
            llm_RE = {
                "relations" : relations,
                "model" : self.llm_re_model,
                "tokens_used" : tokens_used
            }
            self.logger.info(f"List of llm_RE relations created for \"{title}\"")
        except Exception as e:
            self.logger.info(f"List of llm_RE relations not created for \"{title}\": {e}")
        
        return llm_RE