import json
import llmUtils
import logging
import os
import yaml

from helper import create_logger

class LLMNER:
    def __init__(self):
        # Get Configuration
        self.config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        self.cfg = yaml.load(open(self.config_file_path), Loader=yaml.FullLoader)

        # Logging
        log_file_path = os.path.dirname(os.path.abspath(__file__)) + "/logs/llm_ner.log"
        logging_format = '%(asctime)s - %(message)s'
        self.logger = create_logger('LLM_NER', log_file_path, logging_format, logging.INFO)
        
        # AWS credentials
        self.aws_access_key_id = self.cfg["aws_creds"]["access_key_id"]
        self.aws_secret_access_key = self.cfg["aws_creds"]["secret_access_key"]
        
        # AWS Model
        self.llm_ner_model = self.cfg["aws_models"]["llm_ner_model"]
        self.llm_classifyTA_model = self.cfg["aws_models"]["llm_classifyTA_model"]
        self.aws_region = self.cfg["aws_models"]["region"]
        
        
        
    def construct_extraction_prompt(self, article):
        """
        Constructs a prompt requesting for the extraction of entities from an article to be sent to the LLM 
        
        :param article: the article from which entities are to be extracted from
        :type article: str
        :returns: a list of messages in the specified format to be sent to the LLM 
        :rtype: list
        """
        
        first_user_msg = """
        You are a Named Entity Recognition model which recognizes and classifies named entities accurately.
        You will be provided with a cybersecurity article. The article will be delimited by $$$ characters.
        Based on the definitions of the following named entities, delimited by ''' characters, extract these named entities from the given article.
        
        '''
        "Adversary: Actor": An individual, group, organization, or nation-state engaged in malicious activities with the purpose of causing harm, damage, or disruption to individuals, organizations, or systems.
        "Capabilities: Malware": Unique names for malicious software designed to disrupt, damage, or gain unauthorized access to computer systems. Examples of "Capabilities: Malware" entities include "Emotet", "Covidlock" and "Stuxnet". 
        "Capabilities: Tool": Software or utilities used by an adversary to execute malicious activities, which can include repurposed legitimate software, custom-developed tools, and publicly available hacking tools.
        "Capabilities: Malware Type": A specific category of malicious software distinguished by its behavior, purpose, or method of operation. Examples of "Capabilities: Malware Type" entities include "ransomware", "spyware", "adware", "trojans", "worms", and "viruses".
        "Capabilities: Vulnerability": A weakness or flaw in software, hardware, or organizational processes that can be exploited by an adversary to gain unauthorized access to systems or data. 
        "Victim: Country": The geopolitical entity associated with the victim entity, indicating the nation-state or country where the victim organization is based or operates.
        "Victim: Sector": The specific industry or economic segment to which a victim belongs, such as finance, healthcare, energy, government, or telecommunications. This helps in understanding the targeted sector's significance and potential impact.
        "Victim: Region": The geographical area where victims are located. Regions can be defined on various scales, including continental, sub-continental, sub-national, or specific areas within a city.
        "Victim: Name": The name or identifier of the victim entity affected by a cyber incident or threat activity, such as individuals, organizations, companies, etc.
        "Infra: Domain Name": A human-readable address used to identify a resource on the internet, such as a website. Domain names can be used for legitimate purposes or by adversaries to host malicious content or command-and-control servers. An example of an "Infra: Domain Name" entity is "mail.google.com".
        "Infra: Service": Refers to underlying applications and web-based services used in the context of a cyberattack, including legitimate services abused for malicious purposes such as being leveraged as a command-and-control server.
        '''

        For each identified named entity, extract the following information, delimited by ### characters, then output them in JSON format. 

        ###
        "pretty_label": type of named entity
        "text": the identified named entity
        ###

        Return your response as a JSON string without the JSON markdown.
        
        $$$
        A ransomware attack that hit pathology services provider Synnovis on Monday and impacted several major NHS hospitals in London has now been linked to the Qilin ransomware operation. 
        Ciaran Martin, the inaugural CEO of the UK's National Cyber Security Centre (NCSC), said today that the Qilin gang is likely responsible for the incident.
        The attack has resulted in Synnovis being locked out of its systems and is causing ongoing service disruptions at Guy's and St Thomas' NHS Foundation Trust, King's College Hospital NHS Foundation Trust, and various primary care providers across south east London.
        $$$
        """

        example_output1 = """
        {
            "entities": [
                {
                    "pretty_label": "Capabilities: Malware Type",
                    "text": "ransomware"
                },
                {
                    "pretty_label": "Victim: Name",
                    "text": "Synnovis"
                },
                {
                    "pretty_label": "Victim: Region",
                    "text": "London"
                },
                {
                    "pretty_label": "Adversary: Actor",
                    "text": "Qilin"
                },
                {
                    "pretty_label": "Victim: Name",
                    "text": "Guy's and St Thomas' NHS Foundation Trust"
                },
                {
                    "pretty_label": "Victim: Name",
                    "text": "King's College Hospital NHS Foundation Trust"
                }
            ]
        } 
        """
        example_input2 = """
        $$$
        A month-long phishing campaign by the Russia-aligned threat actor group FlyingYeti has been leveraging a WinRAR vulnerability to deliver the Cookbox malware to Ukrainians. 
        Also known as UAC-0149 by the Computer Emergency Response Team of Ukraine (CERT-UA), FlyingYeti has previously primarily conducted attacks on the country's military entities, but extended its focus to include civilian targets in the latest campaign.
        FlyingYeti's phishing emails and Signal messages impersonated the country's housing authority, Kyiv Komunalka, and its website, urging recipients to download a Microsoft Word document which then retrieved a WinRAR archive file from a GitHub-hosted site. WinRAR is a file archiver utility for Windows.
        $$$
        """

        example_output2 = """
        {
            "entities": [
                {
                    "pretty_label": "Adversary: Actor",
                    "text": "FlyingYeti"
                },
                {
                    "pretty_label": "Capabilities: Malware",
                    "text": "Cookbox"
                },
                {
                    "pretty_label": "Victim: Name",
                    "text": "Ukrainians"
                },
                {
                    "pretty_label": "Adversary: Actor",
                    "text": "UAC-0149"
                },
                {
                    "pretty_label": "Victim: Sector",
                    "text": "military"
                },
                {
                    "pretty_label": "Victim: Sector",
                    "text": "civilian"
                },
                {
                    "pretty_label": "Capabilities: Tool"
                    "text": "Microsoft Word"
                },
                {
                    "pretty_label": "Capabilities: Tool"
                    "text": "WinRAR"
                },
                {
                    "pretty_label": "Infra: Service"
                    "text": "Github"
                }
            ]
        }
        """
        
        example_input3 = """
        $$$
        Researchers have found evidence of a link between the global crimeware organization Trickbot and the North Korean APT group Lazarus, observing direct collaboration via an all-in-one attack framework developed by Trickbot called Anchor Project. This unprecedented connection spells trouble for global banks and other cybercrime targets. The move appears to be the first time an APT group has aligned itself with a major force in crimeware, which has significant national security implications in the United States and spells trouble for Lazarus targets, which already have included some top multinationals. Additionally, threat actors are abusing the free graphics design website Canva to create and host intricate spear-phishing landing pages. 
        An example file is hello.pdb. Command and control test File Transfer Protocols were observed, with the threat actor appearing to download the file rclone.exe directly from rclone[.]org. The download link was hxxps://downloads.rclone[.]org/v1.54.0/rclone-v1.54.0-windows-amd64.zip.
        $$$
        """

        example_output3 = """
        {
            "entities": [
                {
                    "pretty_label": "Adversary: Actor",
                    "text": "Trickbot"
                },
                {
                    "pretty_label": "Adversary: Actor",
                    "text": "Lazarus"
                },
                {
                    "pretty_label": "Capabilities: Tool",
                    "text": "Anchor Project"
                },
                {
                    "pretty_label": "Victim: Country",
                    "text": "United States"
                },
                {
                    "pretty_label": "Infra: Domain Name",
                    "text": "rclone[.]org"
                }
            ]
        }
        """

        delimiter = "$$$"
        messages = [{"role": "user", "content": [{"text": first_user_msg}]},
                {"role": "assistant", "content": [{"text": example_output1}]},
                {"role": "user", "content": [{"text": example_input2}]},
                {"role": "assistant", "content": [{"text": example_output2}]},
                {"role": "user", "content": [{"text": example_input3}]},
                {"role": "assistant", "content": [{"text": example_output3}]},
                {"role": "user", "content": [{"text": f"{delimiter}\n{article}\n{delimiter}"}]}]
        return messages
    
    def construct_validation_prompt(self, article, combined_entities):
        """
        Constructs a prompt requesting for the validation of entities to be sent to the LLM
        
        :param article: the article from which entities are to be extracted from
        :type article: str
        :param combined_entities: spacy-extracted entities + llm-extracted entities to be validated 
        :type combined_entities: str
        :returns: a list of messages in the specified format to be sent to the LLM 
        :rtype: list
        """
        first_user_msg = """
        You are a Named Entity Recognition model which recognizes and classifies named entities accurately.
        You will be provided with a cybersecurity article. The article will be delimited by $$$ characters.
        You will also be provided with a list of named entities in JSON format, delimited by *** characters.
        Based on the definitions of the following named entities, delimited by ''' characters, determine if the named entities in the given list have been classified correctly in the context of the given article. 
        
        '''
        "Adversary: Actor": An individual, group, organization, or nation-state engaged in malicious activities with the purpose of causing harm, damage, or disruption to individuals, organizations, or systems.
        "Capabilities: Malware": Unique names for malicious software designed to disrupt, damage, or gain unauthorized access to computer systems. Examples of "Capabilities: Malware" entities include "Emotet", "Covidlock" and "Stuxnet". 
        "Capabilities: Tool": Software or utilities used by an adversary to execute malicious activities, which can include repurposed legitimate software, custom-developed tools, and publicly available hacking tools.
        "Capabilities: Malware Type": A specific category of malicious software distinguished by its behavior, purpose, or method of operation. Examples of "Capabilities: Malware Type" entities include "ransomware", "spyware", "adware", "trojans", "worms", and "viruses".
        "Capabilities: Vulnerability": A weakness or flaw in software, hardware, or organizational processes that can be exploited by an adversary to gain unauthorized access to systems or data. 
        "Victim: Country": The geopolitical entity associated with the victim entity, indicating the nation-state or country where the victim organization is based or operates.
        "Victim: Sector": The specific industry or economic segment to which a victim belongs, such as finance, healthcare, energy, government, or telecommunications. This helps in understanding the targeted sector's significance and potential impact.
        "Victim: Region": The geographical area where victims are located. Regions can be defined on various scales, including continental, sub-continental, sub-national, or specific areas within a city.
        "Victim: Name": The name or identifier of the victim entity affected by a cyber incident or threat activity, such as individuals, organizations, companies, etc.
        "Infra: Domain Name": A human-readable address used to identify a resource on the internet, such as a website. Domain names can be used for legitimate purposes or by adversaries to host malicious content or command-and-control servers. An example of an "Infra: Domain Name" entity is "mail.google.com".
        "Infra: Service": Refers to underlying applications and web-based services used in the context of a cyberattack, including legitimate services abused for malicious purposes such as being leveraged as a command-and-control server.
        '''

        For each given named entity, output them in JSON format containing the following information, delimited by ### characters. 
        ###
        "pretty_label": given type of named entity
        "text": the identified named entity
        "new_label": corrected type of named entity
        ###
        
        Return "NA" for the "new label" property if the identified named entity does not fall into the list of entities provided. 
        Return your response as a JSON string without the JSON markdown.

        $$$
        A ransomware attack that hit pathology services provider Synnovis on Monday and impacted several major NHS hospitals in London has now been linked to the Qilin ransomware operation. 
        Ciaran Martin, the inaugural CEO of the UK's National Cyber Security Centre (NCSC), said today that the Qilin gang is likely responsible for the incident
        The attack has resulted in Synnovis being locked out of its systems and is causing ongoing service disruptions at Guy's and St Thomas' NHS Foundation Trust, King's College Hospital NHS Foundation Trust, and various primary care providers across south east London.
        $$$
        
        ***
        {
            "entities": [
                {
                    "pretty_label": "Capabilities: Malware Type",
                    "text": "ransomware"
                },
                {
                    "pretty_label": "Adversary: Actor",
                    "text": "Synnovis"
                },
                {
                    "pretty_label": "Victim: Region",
                    "text": "London"
                },
                {
                    "pretty_label": "Infra: Service",
                    "text": "Qilin"
                },
                {
                    "pretty_label": "Capabilities: Malware",
                    "text": "Guy's and St Thomas' NHS Foundation Trust"
                },
                {
                    "pretty_label": "Victim: Name",
                    "text": "King's College Hospital NHS Foundation Trust"
                }
            ]
        }
        ***
        """

        example_output1 = """
        {
            "entities": [
                {
                    "pretty_label": "Capabilities: Malware Type",
                    "text": "ransomware",
                    "new_label": "Capabilities: Malware Type"
                },
                {
                    "pretty_label": "Adversary: Actor",
                    "text": "Synnovis",
                    "new_label": "Victim: Name"
                },
                {
                    "pretty_label": "Victim: Region",
                    "text": "London",
                    "new_label": "Victim: Region"
                },
                {
                    "pretty_label": "Infra: Service",
                    "text": "Qilin",
                    "new_label": "Adversary: Actor"
                },
                {
                    "pretty_label": "Capabilities: Malware",
                    "text": "Guy's and St Thomas' NHS Foundation Trust",
                    "new_label": "Victim: Name"
                },
                {
                    "pretty_label": "Victim: Name",
                    "text": "King's College Hospital NHS Foundation Trust",
                    "new_label": "Victim: Name"
                }
            ]
        } 
        """

        example_input2 = """
        $$$
        A month-long phishing campaign by the Russia-aligned threat actor group FlyingYeti has been leveraging a WinRAR vulnerability to deliver the Cookbox malware to Ukrainians. 
        Also known as UAC-0149 by the Computer Emergency Response Team of Ukraine (CERT-UA), FlyingYeti has previously primarily conducted attacks on the country's military entities, but extended its focus to include civilian targets in the latest campaign.
        FlyingYeti's phishing emails and Signal messages impersonated the country's housing authority, Kyiv Komunalka, and its website, urging recipients to download a Microsoft Word document which then retrieved a WinRAR archive file from a GitHub-hosted site. WinRAR is a file archiver utility for Windows.
        $$$
        
        ***
        {
            "entities": [
                {
                    "pretty_label": "Victim: Name",
                    "text": "FlyingYeti"
                },
                {
                    "pretty_label": "Capabilities: Malware Type",
                    "text": "Cookbox"
                },
                {
                    "pretty_label": "Victim: Country",
                    "text": "Ukrainians"
                },
                {
                    "pretty_label": "Adversary: Actor",
                    "text": "UAC-0149"
                },
                {
                    "pretty_label": "Victim: Sector",
                    "text": "military"
                },
                {
                    "pretty_label": "Victim: Sector",
                    "text": "civilian"
                },
                {
                    "pretty_label": "Capabilities: Malware",
                    "text": "phishing emails"
                },
                {
                    "pretty_label": "Victim: Name",
                    "text": "Microsoft Word"
                },
                {
                    "pretty_label": "Capabilities: Tool",
                    "text": "WinRAR"
                },
                {
                    "pretty_label": "Infra: Service",
                    "text": "Github"
                }
            ]
        }
        ***
        """

        example_output2 = """
        {
            "entities": [
                {
                    "pretty_label": "Victim: Name",
                    "text": "FlyingYeti",
                    "new_label": "Adversary: Actor"
                },
                {
                    "pretty_label": "Capabilities: Malware Type",
                    "text": "Cookbox",
                    "new_label": "Capabilities: Malware"
                },
                {
                    "pretty_label": "Victim: Country",
                    "text": "Ukrainians",
                    "new_label": "Victim: Name"
                },
                {
                    "pretty_label": "Adversary: Actor",
                    "text": "UAC-0149",
                    "new_label": "Adversary: Actor"
                },
                {
                    "pretty_label": "Victim: Sector",
                    "text": "military",
                    "new_label": "Victim: Sector"
                },
                {
                    "pretty_label": "Victim: Sector",
                    "text": "civilian",
                    "new_label": "Victim: Sector"
                },
                {
                    "pretty_label": "Capabilities: Malware",
                    "text": "phishing emails"
                    "new_label": "NA"
                },
                {
                    "pretty_label": "Victim: Name",
                    "text": "Microsoft Word",
                    "new_label": "Capabilities: Tool"
                },
                {
                    "pretty_label": "Capabilities: Tool",
                    "text": "WinRAR",
                    "new_label": "Capabilities: Tool"
                },
                {
                    "pretty_label": "Infra: Service",
                    "text": "Github",
                    "new_label": "Infra: Service"
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
                    {"role": "user", "content": [{"text": f"{article_delimiter}\n{article}\n{article_delimiter}\n\n{entities_delimiter}\n{combined_entities}\n{entities_delimiter}"}]}]	
        return messages    
    

    def construct_threat_actor_classification_prompt(self, article, threat_actors):
        """
        Constructs a prompt requesting for the classification of threat actor entities to be sent to the LLM 
        
        :param article: the article from which entities are extracted from
        :type article: str
        :param threat_actors: threat actor entities to be classified 
        :type threat_actors: str
        :returns: a list of messages in the specified format to be sent to the LLM
        :rtype: list
        """
        first_user_msg = """
        You are a Named Entity Recognition model which recognizes and classifies threat actor entities accurately.
        You will be provided with a cybersecurity article. The article will be delimited by $$$ characters.
        You will also be provided with a list of threat actor entities in JSON format, delimited by *** characters.
        Based on the definitions of the following types of threat actors, delimited by ''' characters, classify the threat actor entities in the given list into their respective types 
        with reference to the context of the given article. 
        
        '''
        "Advanced Persistent Threat (APT)": Refers to a group of threat actors or organizations that carry out sophisticated and prolonged cyberattacks. Typically state-sponsored or highly skilled, APTs aim to steal sensitive data, disrupt operations, or conduct espionage, using persistence and advanced tactics to evade detection.
        "Hacktivist": Refers to an individual or group that uses hacking techniques to promote political, social, or ideological agendas. Hacktivists are driven by activism and may target organizations, governments, or individuals to protest against perceived injustices or to promote their causes. 
        "Cybercriminal": Refers to an individual or group that engages in illegal activities using computers, networks, or the internet as their primary tools. Motivated primarily by financial gain, cybercriminals carry out activities such as identity theft, fraud, ransomware attacks, phishing, and the sale of stolen data on the dark web.
        '''

        For each given named entity, output them in JSON format containing the following information, delimited by ### characters. 
        ###
        "text" : the identified named entity
        "threat_actor_type" : type of threat actor entity
        ###
        
        Return "NA" for the "threat_actor_type" property if the identified threat actor entity does not fit into the threat actor categories that was provided.
        Return your response as a JSON string without the JSON markdown.
        
        $$$
        A threat group linked to Iran's Islamic Revolutionary Guard Corps (IRGC) has launched new cyberattacks against email accounts associated with the upcoming US presidential election as well as high-profile military 
        and other political targets in Israel. The activity — which predominantly comes in the form of socially engineered phishing campaigns — are in retaliation for Israel's ongoing military campaign in Gaza and the US' 
        support for it, and are expected to continue as tensions rise in the region. Google's Threat Analysis Group (TAG) detected and blocked "numerous" attempts by Iran-backed APT42, perhaps best known as Charming Kitten, 
        to log in to the personal email accounts of about a dozen individuals affiliated with President Biden and with former President Trump, according to a blog post published yesterday. Targets of the activity included 
        current and former US government officials as well as individuals associated with the respective campaigns.
        $$$
        
        ***
        {
            "threat_actors": [
                {
                    "text" : "Iran's Islamic Revolutionary Guard Corps (IRGC)"
                },
                {
                    "text" : "APT42"
                },
                {
                    "text" : "Charming Kitten"
                }
            ]
        }
        ***
        """

        example_output1 = """
        {
            "threat_actors": [
                {
                    "text" : "Iran's Islamic Revolutionary Guard Corps (IRGC)",
                    "threat_actor_type" : "NA"
                },
                {
                    "text" : "APT42",
                    "threat_actor_type" : "Advanced Persistent Threat (APT)"
                },
                {
                    "text" : "Charming Kitten",
                    "threat_actor_type" : "Advanced Persistent Threat (APT)"
                }
            ]
        }
        """

        example_input2 = """
        $$$
        Hacktivist cyber activities around the Israel-Hamas conflict have significantly slowed, with some groups no longer plotting such attacks and others focusing on targets outside Israel.
        Research of Dark Web discussions released this month by Security Scorecard found several hacktivist groups had made plans to conduct attacks or identified targets to be attacked, but many groups have since fallen silent or resorted to selling attack services.
        A pro-Palestinian group, Dark Storm Team, posted claims in August 2023 on Dark Web forums that it would "attack Israel infrastructure," and in early October, claimed to be preparing attacks against Israel's European allies. However, as of Oct. 20, it had reverted to promoting its DDoS-as-a-service options.
        Many hacktivist groups threatened to launch disruptive attacks against Israel and Palestine, while the hacktivist group SiegedSec claimed responsibility for a series of attacks against Israeli infrastructure and industrial control systems.
        $$$
        
        ***
        {
            "threat_actors": [
                {
                    "text" : "Dark Storm Team"
                },
                {
                    "text" : "SiegedSec"
                }
            ]
        }
        ***
        """

        example_output2 = """
        {
            "threat_actors": [
                {
                    "text" : "Dark Storm Team",
                    "threat_actor_type" : "Hacktivist",
                },
                {
                    "text" : "SiegedSec",
                    "threat_actor_type" : "Hacktivist",
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
                    {"role": "user", "content": [{"text": f"{article_delimiter}\n{article}\n{article_delimiter}\n\n{entities_delimiter}\n{threat_actors}\n{entities_delimiter}"}]}]	
        return messages
    
    def get_llm_entities(self, response, article):
        """
        Gets the entities returned by the LLM and ensure that the entities are strictly from the article provided
        
        :param response: response from the LLM
        :type response: dict
        :param article: article from which entities are extracted from
        :type article: str
        :returns: a list of entities extracted by the LLM
        :rtype: list
        """
        response_text = response["output"]["message"]["content"][0]["text"]
        ent_list = json.loads(response_text)["entities"]
        ent_list = llmUtils.validate_label(ent_list, "pretty_label")
        ent_list = llmUtils.ensure_entities_from_article(ent_list, article)

        return ent_list


    def get_validated_entities(self, response):
        """
        Gets the validated entities returned by the LLM. 
        Removes entities labelled with NA, duplicate entities and entities that are substrings of other entities.
        Entities returned have 3 properties: pretty_label (old label), text, new_label
        
        :param response: response from the LLM
        :type response: dict
        :returns: a final list of validated entities
        :rtype: list
        """
        response_text = response["output"]["message"]["content"][0]["text"]
        ent_list = json.loads(response_text)["entities"]
        ent_list = llmUtils.validate_label(ent_list, "new_label")
        ent_list = llmUtils.remove_NA(ent_list)
        ent_list = llmUtils.remove_dups_after_validation(ent_list)
        ent_list = llmUtils.remove_substring(ent_list)

        return ent_list
    
    def get_threat_actor_classification(self, response):
        """
        Gets the classification of threat actors returned by the LLM
        
        :param response: response from the LLM
        :type response: dict
        :returns: a list of entities extracted by the LLM
        :rtype: list
        """
        response_text = response["output"]["message"]["content"][0]["text"]
        threat_actor_list = json.loads(response_text)["threat_actors"]
        threat_actor_list = llmUtils.validate_threat_actor_types(threat_actor_list)

        return threat_actor_list
    
    
    def improve_entities(self, article, spacy_entities, region, run_get_llm_entities = True):
        """
        Sends 3 prompts to the LLM. First prompt gets LLM-extracted entities. Second prompt validates these entities along with the 
        provided spacy-extracted entities. Third prompt classifies threat actor entities according to their types.
        First prompt only runs if run_get_llm_entities is True.
        Process the results to get a final list of entities, each with 3 properties: 
        (label, pretty_label, text)
        
        :param log: logger object
        :type log: Logger
        :param article: the article from which entities are to be extracted from
        :type article: str
        :param spacy_entities: a list of entities that were previously extracted by spacyNER model
        :type spacy_entities: list
        :param validation_model: LLM model to be used for validation of entities
        :type validation_model: str

        :param run_get_llm_entities: a boolean value indicating whether to get LLM-extracted entities 
        :type run_get_llm_entities: bool
        :param aws_access_key_id: user-provided aws access key id
        :type aws_access_key_id: str
        :param aws_secret_access_key: user-provided aws secret access key
        :type aws_secret_access_key: str
        :param region: user-provided aws region
        :type region: str
        :returns: a tuple containing a final list of entities, a dict showing validation tokens used and a dict showing classifyTA tokens used
        :rtype: tuple(list, dict, dict)
        """
        input_tokens_count = 0
        output_tokens_count = 0
        processed_spacy_entities, remaining_entities = llmUtils.process_spacy_entities(spacy_entities)
        
        
        entities_to_be_validated = llmUtils.get_entities_json(processed_spacy_entities)
        
        # first prompt to LLM to get new list of entities
        if run_get_llm_entities:
            extraction_messages = self.construct_extraction_prompt(article)
            try:
                response1 = llmUtils.prompt_llm(self.llm_ner_model, extraction_messages, self.aws_access_key_id, self.aws_secret_access_key, region)
                if response1["stopReason"] == "max_tokens":
                    raise Exception("Output for extraction of entities exceeded the model's maximum number of tokens")
                llm_entities = self.get_llm_entities(response1, article)
                input_tokens_count = response1["usage"]["inputTokens"]
                output_tokens_count = response1["usage"]["outputTokens"]
                self.logger.info(f"Call to {self.llm_ner_model} for extraction of entities from article successful")
            except Exception as e: 
                self.logger.info(f"Exception occurred while calling {self.llm_ner_model} for extraction of entities from article")
                raise Exception(e)    
        # second prompt to LLM to validate entities
        entities_to_be_validated = llmUtils.combine_entities(processed_spacy_entities, llm_entities)
        validation_messages = self.construct_validation_prompt(article, entities_to_be_validated)
        try:
            response2 = llmUtils.prompt_llm(self.llm_ner_model, validation_messages, self.aws_access_key_id, self.aws_secret_access_key, self.aws_region)
            if response2["stopReason"] == "max_tokens":
                raise Exception("Output for validation of entities exceeded the model's maximum number of tokens")
            validated_entities = self.get_validated_entities(response2)
            validated_entities = llmUtils.add_labels(self.logger, validated_entities) 
            validated_entities = llmUtils.add_back_entities(validated_entities, remaining_entities)
            input_tokens_count += response2["usage"]["inputTokens"]
            output_tokens_count += response2["usage"]["outputTokens"]
            self.logger.info(f"Call to {self.llm_ner_model} for validation of entities successful")
        except Exception as e:
            self.logger.info(f"Exception occurred while calling {self.llm_ner_model} for validation of entities")
            raise Exception(e)

        # get proper format for total tokens used for validation of entities
        validation_tokens = llmUtils.get_token_count(input_tokens_count, output_tokens_count)    
    
        # third prompt to LLM to classify threat actor entities
        input_tokens_count = 0
        output_tokens_count = 0
        non_threat_actors, threat_actors = llmUtils.separate_threat_actors(validated_entities)
        if json.loads(threat_actors)["threat_actors"]: # only runs if there are threat actors in the list of entities
            classification_messages = self.construct_threat_actor_classification_prompt(article, threat_actors)
            try:
                response3 = llmUtils.prompt_llm(self.llm_classifyTA_model, classification_messages, self.aws_access_key_id, self.aws_secret_access_key, self.region)
                if response3["stopReason"] == "max_tokens":
                    raise Exception("Output for classification of threat actors exceeded the model's maximum number of tokens")
                threat_actors = self.get_threat_actor_classification(response3)
                threat_actors = llmUtils.add_threat_actor_labels(threat_actors)
                validated_entities = llmUtils.add_back_threat_actors(non_threat_actors, threat_actors)
                input_tokens_count = response3["usage"]["inputTokens"]
                output_tokens_count = response3["usage"]["outputTokens"]
                self.logger.info(f"Call to {self.llm_classifyTA_model} for classification of threat actor entities successful")
            except Exception as e:
                self.logger.info(f"Exception occurred while calling {self.llm_classifyTA_model} for classification of threat actor entities: {e}")

        # get proper format for total tokens used for classification of threat actors
        classifyTA_tokens = llmUtils.get_token_count(input_tokens_count, output_tokens_count)

        return validated_entities, validation_tokens, classifyTA_tokens    


    def run_llm_NER(self, txt, entities, title, run_get_llm_entities =True):
        """
        Processes text to obtain a final list of validated named entities using a language model.
        This function processes the provided text and entities to extract and validate named entities using a specified language model. 
        It logs the process and handles any exceptions that may occur during the execution.
        :param txt: The text to be processed for named entity recognition.
        :type txt: str
        :param entities: A list of initial entities to be validated and improved.
        :type entities: list
        :param title: The title of the text being processed, used for logging purposes.
        :type title: str
        :param run_get_llm_entities: A boolean indicating whether to extract entities using the language model.
        :type run_get_llm_entities: bool, optional (default is True)
        :returns: A dictionary containing the validated entities and metadata about the validation process.
        :rtype: dict
        """
        
            
        self.logger.info(f"Processing LLM_NER title : \"{title}\"")
        try:
            llm_results = self.improve_entities(txt,entities, self.aws_region, run_get_llm_entities)
            validatedNER = {
                "entities" : llm_results[0],
                "validation_model" : self.llm_ner_model,
                "validation_tokens_used" : llm_results[1],
                "classifyTA_model" : self.llm_classifyTA_model,
                "classifyTA_tokens_used" : llm_results[2]
            }
            self.logger.info(f"List of validatedNER entities created for \"{title}\"")
        except Exception as e:
            self.logger.info(f"List of validatedNER entities not created for \"{title}\": {e}")
        
        return validatedNER