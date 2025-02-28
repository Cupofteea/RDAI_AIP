import json
import llmUtils
import logging
import os
import yaml

from helper import create_logger

class LLMSUMMARY:
    
    def __init__(self):
        # Get configuration
        self.config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        self.cfg = yaml.load(open(self.config_file_path), Loader=yaml.FullLoader)

        # Logging
        log_file_path = os.path.dirname(os.path.abspath(__file__)) + "/logs/llm_summary.log"
        logging_format = '%(asctime)s - %(message)s'
        self.logger = create_logger('LLM_SUMMARY', log_file_path, logging_format, logging.INFO)
        
        # AWS credentials
        self.aws_access_key_id = self.cfg["aws_creds"]["access_key_id"]
        self.aws_secret_access_key = self.cfg["aws_creds"]["secret_access_key"]
        
        # Models
        self.llm_summary_model = self.cfg["aws_models"]["llm_summary_model"]
        self.aws_region = self.cfg["aws_models"]["region"]
        
        
    # Construct prompt to feed into the LLM
    def construct_extraction_prompt(self, article_text):

        # Define the initial user message
        first_user_msg = f"""You are a Cyber Threat Intelligence analyst analysing a cyber threat intelligence report. You will be given a cyber news article. Your task is to extract key information, delimited by ''', from the article, which is delimited by ###, and extractively summarise them. You do not use generative or abstractive text summarisation.
        From the given cyber news article, extract the following key information, delimited by '''. Respond with "NIL" for any information that cannot be found. 
        '''
        "adversary": The implied adversary and its aliases,
        "adversary_capability": Adversary's capability tool or tools used,
        "victim": The implied victim or victims,
        "impact_caused": The impact caused by the implied adversary, if any, to the victim,
        "date_of_attack": The date of attack or attacks, if mentioned,
        "ttp": Tactics, techniques, and procedures (TTPs) mentioned,
        "vulnerabilities": Vulnerabilities, if mentioned,
        "ioc": Indicators of Compromise (IOCs), if mentioned,
        "source_codes": Every chunk of source codes and commands grouped as a JSON key, if mentioned,
        "rule_lists": Every chunk of YARA rule, if mentioned.
        '''
        
        Please extract the specified key information from the cyber news article and return your response as a JSON string without the JSON markdown.
        
        
        ###
        UK arrests suspected Scattered Spider hacker linked to MGM attack
        UK police have arrested a 17-year-old boy suspected of being involved in the 2023 MGM Resorts ransomware attack and a member of the Scattered Spider hacking collective.
        "We have arrested a 17-year-old boy from Walsall in connection with a global cyber online crime group which has been targeting large organisations with ransomware and gaining access to computer networks," reads a statement from the West Midlands Police in the United Kingdom.
        "Officers from our Regional Organised Crime Unit for the West Midlands (ROCUWM) joined officers from the National Crime Agency, in coordination with the United States Federal Bureau of Investigation (FBI), to make the arrest at an address in the town on Thursday (July 18)."
        The teenager was arrested on suspicion of violating the Blackmail and Computer Misuse Act and was subsequently released on bail while the police completed their investigation.
        The authorities have also seized digital devices from the suspect that will be investigated for further evidence.
        "We're proud to have assisted law enforcement in locating and arresting one of the alleged criminals responsible for the cyber attack against MGM Resorts and many others," MGM said as part of the law enforcement statement.
        The UK police say that the arrest is part of a broader investigation conducted by the National Crime Agency and the FBI into a hacking group known to breach networks, steal data, and deploy ransomware in extortion schemes.
        While not explicitly stated in the police statement, the hacking collective behind the MGM attack is known as Scattered Spider.
        The name "Scattered Spider" denotes a loose-knit community of English-speaking threat actors (as young as 16) with diverse skill sets who commonly frequent the same Telegram channels, Discord servers, and hacker forums.
        Some members are also believed to be part of the "Comm" - another hacking collective linked to violent acts and cyber incidents.
        Contrary to the general belief that the Scattered Spider is a cohesive gang, it is a network of individuals with a large pool of threat actors participating in different attacks.
        This fluid structure makes it difficult for law enforcement to track them or attribute attacks to a specific cybercrime group.
        Scattered Spider is also known as 0ktapus, Starfraud, UNC3944, Scatter Swine, Octo Tempest, and Muddled Libra.
        In a 2023 FBI advisory, law enforcement outlined the hacking collective's skills and tactics, which include social engineering, phishing, multi-factor authentication (MFA) bombing (targeted MFA fatigue), and SIM swapping to breach corporate networks.
        Over the past year, the threat actors in this "community" have taken the unusual approach of partnering with Russian ransomware gangs, including BlackCat/AlphV, Qilin, and RansomHub.
        Other attacks attributed to Scattered Spider include Caesars, DoorDash, MailChimp, Twilio, Riot Games, and Reddit.
        Post a Comment Community Rules
        You need to login in order to post a comment
        Not a member yet? Register Now
        ###
        """

        example_output1 = """
        {
            "adversary": "Scattered Spider, 0ktapus, Starfraud, UNC3944, Scatter Swine, Octo Tempest, Muddled Libra",
            "adversary_capability": "social engineering, phishing, multi-factor authentication (MFA) bombing, SIM swapping",
            "victim": "MGM Resorts, Caesars, DoorDash, MailChimp, Twilio, Riot Games, Reddit",
            "impact_caused": "Ransomware attacks, data theft, extortion schemes",
            "date_of_attack": "2023",
            "ttp": "breach networks, steal data, deploy ransomware",
            "vulnerabilities": "NIL",
            "ioc": "NIL",
            "source_codes": "NIL",
            "rule_lists": "NIL"
        }
        """

        # Construct the initial prompt to feed into the LLM
        article_delimiter = "###"
        messages = [{"role": "user", "content": [{"text": first_user_msg}]},
                    {"role": "assistant", "content": [{"text": example_output1}]},
                    {"role": "user", "content": [{"text": f"{article_delimiter}\n{article_text}\n{article_delimiter}"}]}]

        return messages
    
    
    
    def construct_summary_prompt(self, article_text, resp_content):

        first_user_msg = """
        You are a Cyber Threat Intelligence analyst analysing a cyber threat intelligence report. You will be given a cyber news article, delimited by $$$ characters. You will also be given a list of key information that has been extracted from the article, delimited by ^^^. 
        Using the information that has been extracted from the article, write a summary following the summarised_template given below. Replace the variables, delimited by ###, with the extracted information. 
        The summarised_template is to be written in proper English language and grammatical structure, such as including the use of nouns and verbs. Return your response as a JSON string without the JSON markdown.
        
        "summarised_template": "###date_of_attack###, it was observed that ###adversary### had ###summary of impact caused to implied victim###. The adversary was assessed to have used ###adversary's capability tool### to ###impact caused###."
        
        After you have written the summary, it is important to proof-read and review your summarised_template to ensure that there is no duplicated information. If there is, then reword the duplicated information.
        

        ###
        UK arrests suspected Scattered Spider hacker linked to MGM attack
        UK police have arrested a 17-year-old boy suspected of being involved in the 2023 MGM Resorts ransomware attack and a member of the Scattered Spider hacking collective.
        "We have arrested a 17-year-old boy from Walsall in connection with a global cyber online crime group which has been targeting large organisations with ransomware and gaining access to computer networks," reads a statement from the West Midlands Police in the United Kingdom.
        "Officers from our Regional Organised Crime Unit for the West Midlands (ROCUWM) joined officers from the National Crime Agency, in coordination with the United States Federal Bureau of Investigation (FBI), to make the arrest at an address in the town on Thursday (July 18)."
        The teenager was arrested on suspicion of violating the Blackmail and Computer Misuse Act and was subsequently released on bail while the police completed their investigation.
        The authorities have also seized digital devices from the suspect that will be investigated for further evidence.
        "We're proud to have assisted law enforcement in locating and arresting one of the alleged criminals responsible for the cyber attack against MGM Resorts and many others," MGM said as part of the law enforcement statement.
        The UK police say that the arrest is part of a broader investigation conducted by the National Crime Agency and the FBI into a hacking group known to breach networks, steal data, and deploy ransomware in extortion schemes.
        While not explicitly stated in the police statement, the hacking collective behind the MGM attack is known as Scattered Spider.
        The name "Scattered Spider" denotes a loose-knit community of English-speaking threat actors (as young as 16) with diverse skill sets who commonly frequent the same Telegram channels, Discord servers, and hacker forums.
        Some members are also believed to be part of the "Comm" - another hacking collective linked to violent acts and cyber incidents.
        Contrary to the general belief that the Scattered Spider is a cohesive gang, it is a network of individuals with a large pool of threat actors participating in different attacks.
        This fluid structure makes it difficult for law enforcement to track them or attribute attacks to a specific cybercrime group.
        Scattered Spider is also known as 0ktapus, Starfraud, UNC3944, Scatter Swine, Octo Tempest, and Muddled Libra.
        In a 2023 FBI advisory, law enforcement outlined the hacking collective's skills and tactics, which include social engineering, phishing, multi-factor authentication (MFA) bombing (targeted MFA fatigue), and SIM swapping to breach corporate networks.
        Over the past year, the threat actors in this "community" have taken the unusual approach of partnering with Russian ransomware gangs, including BlackCat/AlphV, Qilin, and RansomHub.
        Other attacks attributed to Scattered Spider include Caesars, DoorDash, MailChimp, Twilio, Riot Games, and Reddit.
        Post a Comment Community Rules
        You need to login in order to post a comment
        Not a member yet? Register Now
        ###

        ^^^
        {
            "adversary": "Scattered Spider, 0ktapus, Starfraud, UNC3944, Scatter Swine, Octo Tempest, Muddled Libra",
            "adversary_capability": "social engineering, phishing, multi-factor authentication (MFA) bombing, SIM swapping",
            "victim": "MGM Resorts, Caesars, DoorDash, MailChimp, Twilio, Riot Games, Reddit",
            "impact_caused": "Ransomware attacks, data theft, extortion schemes",
            "date_of_attack": "2023",
            "ttp": "breach networks, steal data, deploy ransomware",
            "vulnerabilities": "NIL",
            "ioc": "NIL",
            "source_codes": "NIL",
            "rule_lists": "NIL"
        }
        ^^^
        """

        example_output1 = """
        {
            "summarised_template": "In 2023, it was observed that Scattered Spider, 0ktapus, Starfraud, UNC3944, Scatter Swine, Octo Tempest, and Muddled Libra targeted MGM Resorts, Caesars, DoorDash, MailChimp, Twilio, Riot Games, and Reddit with ransomware attacks, data theft, and extortion schemes. The adversary was assessed to have used social engineering, phishing, multi-factor authentication (MFA) bombing, and SIM swapping to breach networks, steal data, and deploy ransomware."
        }
        """

        # Construct the initial prompt to feed into the LLM
        article_delimiter = "###"
        extracted_info_delimiter = "^^^"
        messages = [{"role": "user", "content": [{"text": first_user_msg}]},
                    {"role": "assistant", "content": [{"text": example_output1}]},
                    {"role": "user", "content": [{"text": f"{article_delimiter}\n{article_text}\n{article_delimiter}\n\n{extracted_info_delimiter}\n{resp_content}\n{extracted_info_delimiter}"}]}]	
        return messages
    
    
    
    
    def format_response(self, model, response, article_text, aws_access_key_id, aws_secret_access_key, region):

        # Prompt LLM for the article's summary
        messages = self.construct_summary_prompt(article_text, response["output"]["message"]["content"][0]["text"])
        resp_summary = llmUtils.prompt_llm(model, messages, aws_access_key_id, aws_secret_access_key, region)
        if resp_summary["stopReason"] == "max_tokens":
            raise Exception("Output for generation of summary exceeded the model's maximum number of tokens")
        summary = json.loads(resp_summary["output"]["message"]["content"][0]["text"])["summarised_template"]

        """ Parse LLM responses into JSON format """
        resp_content = json.loads(response["output"]["message"]["content"][0]["text"])

        # If no date is mentioned in Summary, then state so
        if "It was observed" in summary:
            summary = f"On an unspecified date, it {' '.join(summary.split(' ')[1:])}"
        elif "NIL" in resp_content["date_of_attack"]:
            summary = f"On an unspecified date,{','.join(summary.split(',')[1:])}"

        # Extract relevant details to JSON
        input_tokens = response["usage"]["inputTokens"] + resp_summary["usage"]["inputTokens"]
        output_tokens = response["usage"]["outputTokens"] + resp_summary["usage"]["outputTokens"]
        
        json_response = {
            "model": model,
            "summary": summary,
            "finish_reason": response["stopReason"],
            "tokens_used": {
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "total_tokens": input_tokens + output_tokens
            }
        }

        return json_response


    
    
    def llm_response(self, model, article_text, aws_access_key_id, aws_secret_access_key, region):

        # Remove all non-ASCII characters from article_text
        article_text = "".join(char for char in article_text if 0 < ord(char) < 127)
        
        # Prompt LLM to get the article's adversary and their capability, victim and the impact caused
        messages = self.construct_extraction_prompt(article_text)
        
        try:
            self.logger.info(f"Call to {self.llm_summary_model} for article summarisation")
            response = llmUtils.prompt_llm(model, messages, aws_access_key_id, aws_secret_access_key, region)
            if response["stopReason"] == "max_tokens":
                raise Exception("Output for extraction of key details exceeded the model's maximum number of tokens")
        except Exception as e:
            self.logger.error(f"Error in calling the LLM model for article summarisation: {e}")
        # Format the results from LLM into a JSON object
        json_response = self.format_response(model, response, article_text, aws_access_key_id, aws_secret_access_key, region)

        return json_response


    """ Apply inference on a selected LLM to extract details from an article's text and summarise it """
    def apply_inference(self, article_text):
        
        self.logger.info("Applying inference on the LLM to extract details from the article's text and summarise it")
        
        json_response = self.llm_response(self.llm_summary_model, article_text, self.aws_access_key_id, self.aws_secret_access_key, self.aws_region)
        
        self.logger.info("Inference on the LLM to extract details from the article's text and summarise it has been completed")

        return json_response

    
    
    