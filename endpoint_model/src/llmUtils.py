import json
import boto3


def prompt_llm(model, messages, aws_access_key_id, aws_secret_access_key, region):
    """
    Sends a prompt to the specified model with the Converse API.
    
    :param model: model to be used
    :type model: str
    :param messages: a list of messages in the specified format to be sent to the LLM
    :type messages: list
    :param aws_access_key_id: user-provided aws access key id
    :type aws_access_key_id: str
    :param aws_secret_access_key: user-provided aws secret access key
    :type aws_secret_access_key: str
    :param region: user-provided aws region
    :type region: str
    :returns: response from the LLM  
    :rtype: dict
    """
    # Create a Bedrock Runtime client
    
    client = boto3.client("bedrock-runtime", region_name=region, aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)
    
    response = client.converse(
        modelId=model,
        messages=messages,
        inferenceConfig={"temperature": 0.0, "topP": 0.9}
    )
    return response


def get_token_count(input_tokens_count, output_tokens_count):
    """
    Gets the tokens used for interaction with the LLM and format them into a dict
    
    :param input_tokens_count: total number of prompt tokens used
    :type input_tokens_count: int
    :param output_tokens_count: total number of completion tokens used
    :type output_tokens_count: int
    :returns: a dict showing tokens used
    :rtype: dict
    """
    tokens_used = {
        "input_tokens" : input_tokens_count,
        "output_tokens" : output_tokens_count,
        "total_tokens" : input_tokens_count + output_tokens_count
    }
    return tokens_used



# Specific functions for NER:

def remove_dups(entities):
    """
    Removes duplicate entities from a list

    :param entities: a list of entities with possible duplicates
    :type entities: list
    :returns: a list of entities with no duplicates
    :rtype: list
    """
    seen = set()
    res = []
    for ent in entities:
        ent_tuple = tuple(ent.items())
        if ent_tuple not in seen:
            res.append(ent)
            seen.add(ent_tuple)
    return res


def process_spacy_entities(spacy_entities):
    """
    Removes redundant properties from entities, remove duplicate entities and extract entities that will not be validated

    :param spacy_entities: a list of entities from spacyNER
    :type spacy_entities: list
    :returns: a tuple containing a list of entities to be validated and a list of entities that will not be validated
    :rtype: tuple(list, list)
      """
    # list of entities that will not be validated
    blacklist = ["Capabilities: PDB Path", 
                  "Capabilities: File",
                "Capabilities: SHA256 Hash",
                "Capabilities: SHA1 Hash",
                "Capabilities: MD5 Hash",
                "Capabilities: Directories",
                "Infra: URL",
                "Infra: IPv4",
                "Infra: IPv6",
                "Infra: MAC Address",
                "Infra: Email Address",
                "Metadata: Campaign"]

    filtered_entities = [] # entities that will be validated
    remaining_entities = [] # entities that will not be validated

    for ent in spacy_entities:
        pretty_label = ent["pretty_label"]
        # add entities that will be validated to list
        if ent["label"] != "MITRE_TTP" and pretty_label not in blacklist:
            new_ent = {
                "pretty_label" : pretty_label,
                "text" : ent["text"]
            }
            filtered_entities.append(new_ent)
        # add entities that will not be validated to list
        else:
            new_ent = {
                "label" : ent["label"],
                "pretty_label" : ent["pretty_label"],
                "text" : ent["text"]
            }
            remaining_entities.append(new_ent)

    return remove_dups(filtered_entities), remove_dups(remaining_entities)


def validate_label(entities, label):
    """
    Checks that the pretty_label of entities are valid, otherwise remove the entity from the list

    :param entities: a list of entities 
    :type entities: list
    :param label: the specific name for the pretty_label (pretty_label or new_label)
    :type label: str
    :returns: a list of entities with valid pretty_labels
    :rtype: list
    """
    pretty_label_list = [
        "Adversary: Actor",
        "Capabilities: Malware",
        "Capabilities: Tool",
        "Capabilities: Malware Type",
        "Capabilities: Vulnerability",
        "Victim: Country",
        "Victim: Sector",
        "Victim: Region",
        "Victim: Name",
        "Infra: Domain Name",
        "Infra: Service"
    ]
    validated_list = []
    for ent in entities:
        if ent[label] in pretty_label_list:
            validated_list.append(ent)
    return validated_list


def ensure_entities_from_article(entities, article):
    """
    Checks that entities from the given list are in the given article, otherwise remove it from the list

    :param entities: a list of entities 
    :type entities: list
    :param article: article from which entities should be identified from
    :type article: str
    :returns: a list of entities which are guaranteed to be taken from the article
    :rtype: list
    """
    validated_list = []
    for ent in entities:
        if ent["text"] in article:
            validated_list.append(ent)
    return validated_list	


def combine_entities(spacy_entities, llm_entities):
    """
    Combines the processed spacy entities with the entities extracted by the LLM

    :param spacy_entities: a list of processed spacy entities
    :type spacy_entities: list
    :param llm_entities: a list of LLM-extracted entities
    :type llm_entities: list
    :returns: a json string consisting of the combined list of entities
    :rtype: str
    """
    for ent in spacy_entities:
        llm_entities.append(ent)
        
    new_list = remove_dups(llm_entities)
    res = {
        "entities" : new_list
    }
    return json.dumps(res, indent=4)


def get_entities_json(entities):
    """
    Returns a list of entities in json format

    :param entities: a list of entities
    :type entities: list
    :returns: a json string consisting of the list of entities
    :rtype: str
    """
    res = {
        "entities" : entities
    }
    return json.dumps(res, indent=4)


def remove_NA(entities):
    """
    Removes entities that are classified as "NA" ("new_label")

    :param entities: a list of entities (include "new_label": "NA" entities)
    :type entities: list
    :returns: a list of entities (exclude "new_label": "NA" entities)
    :rtype: list
    """
    final_list = []
    for ent in entities:
        if ent["new_label"] != "NA":
            final_list.append(ent)

    return final_list


def remove_dups_after_validation(entities):
    """
    Removes duplicate entities (entities with same "text" and same "new_label") from a list.
    Entities have 3 properties: "pretty_label", "text" and "new_label".

    :param entities: a list of entities with possible duplicates
    :type entities: list
    :returns: a list of entities with no duplicates
    :rtype: list
    """
    seen = set()
    unique_list = []
    for ent in entities:
        ent_tuple = (ent["text"], ent["new_label"])
        if ent_tuple not in seen:
            unique_list.append(ent)
            seen.add(ent_tuple)

    return unique_list


# function for sorting list of tuple(text, new_label) according to the length of text 
# x = (text, new_label)
def text_len(x):
    return len(x[0])


def remove_substring(entities):
    """
    Removes entities that are substrings of another entity from the same list (entities with same "new_label")

    :param entities: a list of entities
    :type entities: list
    :returns: a list of entities where no other entity within the same list is a substring of another entity
    :rtype: list
    """
    unique_list = []
    entity_list = []
    for ent in entities:
        entity_list.append((ent["text"], ent["new_label"]))
    entity_list.sort(reverse=True, key=text_len)
    
    for ent in entities:
        for text, new_label in entity_list:
            if ent["text"] in text and ent["new_label"] == new_label: # either substring or identical text found
                if ent["text"] == text: # text is identical
                    unique_list.append(ent)
                break
    return unique_list


def add_labels(log, entities):
    """
    Add "label" property to entities based on their "new_label".
    Replaces "new_label" with "pretty_label" for entities.

    :param log: logger object
    :type log: Logger
    :param entities: a list of entities
    :type entities: list
    :returns: a list of entities with 3 properties: "label", "pretty_label" and "text"
    :rtype: list
    """
    res = []
    for ent in entities:
        label = ""
        pretty_label = ent["new_label"]
        text = ent["text"]
        if pretty_label == "Adversary: Actor":
            label = "A_ACTOR"
        elif pretty_label == "Capabilities: Malware":
            label = "C_MALWARE"
        elif pretty_label == "Capabilities: Tool":
            label = "C_TOOL"
        elif pretty_label == "Capabilities: Malware Type":
            label = "C_MALWARETYPE"
        elif pretty_label == "Capabilities: Vulnerability":
            label = "VULN"
        elif pretty_label == "Victim: Country":
            label = "COUNTRY"
        elif pretty_label == "Victim: Sector":
            label = "V_SECTOR"
        elif pretty_label == "Victim: Region":
            label = "REGION"
        elif pretty_label == "Victim: Name":
            label = "V_NAME"
        elif pretty_label == "Infra: Domain Name":
            label = "I_NAME"
        elif pretty_label == "Infra: Service":
            label = "I_SERVICE"
        else:
            log.info(f"Removed entity (\"{text}\") with unrecognised pretty_label (\"{pretty_label}\")")
            continue	
        new_ent = {
            "label" : label,
            "pretty_label" : pretty_label,
            "text" : ent["text"]
        }
        res.append(new_ent)
    return res


def add_back_entities(validated_entities, remaining_entities):
    """
    Add in the entities that were not processed back into the list of entities

    :param validated_entities: a list of entities that were validated
    :type validated_entities: list
    :param remaining_entities: a list of entities that were not processed
    :type remaining_entities: list
    :returns: a complete list of entities 
    :rtype: list
    """
    validated_entities.extend(remaining_entities)
    return validated_entities


def separate_threat_actors(entities):
    """
    Separate the threat actors from the non threat actors based on a list of entities 

    :param entities: a list of entities 
    :type entities: list
    :returns: a tuple containing a list of non threat actor entities and a json string consisting of the list of threat actors
    :rtype: tuple(list, str)
    """
    threat_actor_list = []
    non_threat_actor_list = []
    for ent in entities:
        if "ACTOR" in ent["label"]:
            actor_ent = {
                "text": ent["text"]
            }
            threat_actor_list.append(actor_ent)
        else:
            non_threat_actor_list.append(ent)
    actors = {
        "threat_actors" : threat_actor_list
    }
    return non_threat_actor_list, json.dumps(actors, indent=4)


def validate_threat_actor_types(threat_actors):
    """
    Checks that the threat actor types of entities are valid, otherwise remove the entity from the list 
    (includes removing threat actors labelled with "NA" types)

    :param threat_actors: a list of threat actors 
    :type threat_actors: list
    :returns: a list of threat actors with valid types
    :rtype: list
    """
    threat_actor_types = [
        "Advanced Persistent Threat (APT)",
        "Hacktivist",
        "Cybercriminal"
    ]
    validated_list = []
    for actor in threat_actors:
        if actor["threat_actor_type"] in threat_actor_types:
            validated_list.append(actor)
    return validated_list


def add_threat_actor_labels(threat_actors):
    """
    Add the labels and pretty labels for threat actor entities

    :param threat_actors: the list of threat actors that have been classified
    :type threat_actors: list
    :returns: the list of threat actors with labels and pretty labels added 
    :rtype: list
    """
    labelled_threat_actors = []
    for actor in threat_actors:
        threat_actor = {
            "label" : "A_ACTOR",
            "pretty_label" : "Adversary: Actor",
            "text" : actor["text"],
            "threat_actor_type" : actor["threat_actor_type"]
        }
        labelled_threat_actors.append(threat_actor)
    return labelled_threat_actors		


def add_back_threat_actors(non_threat_actors, threat_actors):
    """
    Add the classified threat actors back into the list of other entities

    :param non_threat_actors: the list of non threat actor entities which were not processed for classification
    :type non_threat_actors: list
    :param threat_actors: the list of threat actors that have been classified
    :type threat_actors: list
    :returns: a complete list of entities 
    :rtype: list
    """
    non_threat_actors.extend(threat_actors)
    return non_threat_actors



# Specific functions for RE:
"""
|--------pretty label----------|-------label-------|------stix object------|
"Adversary: Actor"                   A_ACTOR           intrusion-set
"Capabilities: Malware"              C_MALWARE         malware
"Capabilities: Malware Type"         C_MALWARETYPE     malware
"Capabilities: Tool"                 C_TOOL            tool
"Capabilities: Vulnerability"        VULN              vulnerability
"Victim: Country"                    COUNTRY           location
"Victim: Region"                     REGION            location
"Victim: Sector"                     V_SECTOR          identity
"Victim: Name"                       V_NAME            identity
"Infra: Service"                     I_SERVICE         infrastructure
"Infra: Domain Name"                 I_NAME            indicator (domain-name)
"Capabilities: PDB Path",            INDICATOR         indicator
"Capabilities: File",                INDICATOR         indicator (file)
"Capabilities: SHA256 Hash",         INDICATOR         indicator 
"Capabilities: SHA1 Hash",           INDICATOR         indicator
"Capabilities: MD5 Hash",            INDICATOR         indicator
"Capabilities: Directories",         INDICATOR         indicator (directory)
"Infra: URL",                        INDICATOR         indicator (url)
"Infra: IPv4",                       INDICATOR         indicator (ipv4-addr)
"Infra: IPv6",                       INDICATOR         indicator (ipv6-addr)
"Infra: MAC Address",                INDICATOR         indicator (mac-addr)
"Infra: Email Address",              INDICATOR         indicator (email-addr)
"Metadata: Campaign"                 CAMPAIGN          campaign
"""

def get_stix_labels(entities):
    """
    Add stix object labels to each entity based on their labels

    :param entities: a list of named entities
    :type entities: list
    :returns: a json string containing the entities along with their stix object labels
    :rtype: str
    """
    res = []

    for ent in entities:
        stix_obj = ""
        indicator_type = "NA"
        pretty_label = ent["pretty_label"]

        if pretty_label == "Adversary: Actor":
            stix_obj = "intrusion-set"
        elif pretty_label in ["Capabilities: Malware", "Capabilities: Malware Type"]:
            stix_obj = "malware"
        elif pretty_label == "Capabilities: Tool":
            stix_obj = "tool"
        elif pretty_label == "Capabilities: Vulnerability":
            stix_obj = "vulnerability"
        elif pretty_label in ["Victim: Country", "Victim: Region"]:
            stix_obj = "location"
        elif pretty_label in ["Victim: Sector", "Victim: Name"]:
            stix_obj = "identity"
        elif pretty_label == "Infra: Service":
            stix_obj = "infrastructure"
        elif pretty_label in [
            "Infra: Domain Name",
            "Capabilities: PDB Path", 
            "Capabilities: File",
            "Capabilities: SHA256 Hash", 
            "Capabilities: SHA1 Hash", 
            "Capabilities: MD5 Hash",
            "Capabilities: Directories",
            "Infra: URL",
            "Infra: IPv4",
            "Infra: IPv6",
            "Infra: MAC Address",
            "Infra: Email Address"
        ]:
            stix_obj = "indicator"
        elif pretty_label == "Metadata: Campaign":
            stix_obj = "campaign"
        else:
            continue	
        
        if stix_obj == "indicator":
            if pretty_label == "Infra: Domain Name":
                indicator_type = "domain-name"
            elif pretty_label == "Capabilities: File":
                indicator_type = "file"
            elif pretty_label == "Capabilities: Directories":
                indicator_type = "directory"
            elif pretty_label == "Infra: URL":
                indicator_type = "url"
            elif pretty_label == "Infra: IPv4":
                indicator_type = "ipv4-addr"
            elif pretty_label == "Infra: IPv6":
                indicator_type = "ipv6-addr"
            elif pretty_label == "Infra: MAC Address":
                indicator_type = "mac-addr"
            elif pretty_label == "Infra: Email Address":
                indicator_type = "email-addr"

        new_ent = {
            "pretty_label" : pretty_label,
            "entity_name" : ent["text"],
            "entity_type" : stix_obj,
            "indicator_type" : indicator_type
        }
        res.append(new_ent)

    json_entities = {
        "entities" : res
    }

    return json.dumps(json_entities, indent=4)


def remove_unrecog_rs(relationships):
    """
    Filters out relationships that are not recognised (not taken from the provided list of relationships)
    
    :param relationships: a json string containing a list of relationships to be evaluated 
    :type relationships: str
    :returns: a list of recognised relationships
    :rtype: list
    """
    rs_dict = json.loads(relationships)
    recog_rs = []

    relationship_list = [
        "campaign attributed-to intrusion-set",
        "campaign compromises infrastructure",
        "campaign originates-from location",
        "campaign targets identity",
        "campaign targets location",
        "campaign targets vulnerability",
        "campaign uses infrastructure",
        "campaign uses malware",
        "campaign uses tool",
        "identity located-at location",
        "indicator indicates campaign",
        "indicator indicates infrastructure",
        "indicator indicates intrusion-set",
        "indicator indicates malware",
        "indicator indicates tool",
        "infrastructure communicates-with infrastructure",
        "infrastructure communicates-with ipv4-addr",
        "infrastructure communicates-with ipv6-addr",
        "infrastructure communicates-with domain-name",
        "infrastructure communicates-with url",
        "infrastructure consists-of infrastructure",
        "infrastructure consists-of ipv4-addr",
        "infrastructure consists-of ipv6-addr",
        "infrastructure consists-of domain-name",
        "infrastructure consists-of url",
        "infrastructure consists-of directory",
        "infrastructure consists-of file",
        "infrastructure consists-of mac-addr",
        "infrastructure consists-of email-addr",
        "infrastructure controls infrastructure",
        "infrastructure controls malware",
        "infrastructure delivers malware",
        "infrastructure has vulnerability",
        "infrastructure hosts tool",
        "infrastructure hosts malware",
        "infrastructure located-at location",
        "infrastructure uses infrastructure",
        "intrusion-set related-to intrusion-set",
        "intrusion-set works-with intrusion-set",
        "intrusion-set compromises infrastructure",
        "intrusion-set hosts infrastructure",
        "intrusion-set owns infrastructure",
        "intrusion-set originates-from location",
        "intrusion-set targets identity",
        "intrusion-set targets location",
        "intrusion-set targets vulnerability",
        "intrusion-set uses infrastructure",
        "intrusion-set uses malware",
        "intrusion-set uses tool",
        "intrusion-set uses domain-name",
        "malware authored-by intrusion-set",
        "malware beacons-to infrastructure",
        "malware exfiltrate-to infrastructure",
        "malware communicates-with ipv4-addr",
        "malware communicates-with ipv6-addr",
        "malware communicates-with domain-name",
        "malware communicates-with url",
        "malware controls malware",
        "malware downloads malware",
        "malware downloads tool",
        "malware downloads file",
        "malware drops malware",
        "malware drops tool",
        "malware drops file",
        "malware exploits vulnerability",
        "malware originates-from location",
        "malware targets identity",
        "malware targets infrastructure",
        "malware targets location",
        "malware targets vulnerability",
        "malware targets tool",
        "malware uses infrastructure",
        "malware uses malware",
        "malware uses tool",
        "malware variant-of malware",
        "tool delivers malware",
        "tool drops malware",
        "tool has vulnerability",
        "tool targets identity",
        "tool targets infrastructure",
        "tool targets location",
        "tool targets vulnerability",
        "tool uses infrastructure"
    ]

    for rs in rs_dict["relations"]:
        if rs["relationship"] in relationship_list:
            recog_rs.append(rs)

    return recog_rs


def validate_entities_existence(entities, relationships):
    """
    Ensures that the entities involved in the identified relationships are in the previously identified list of entities,
    otherwise remove the relationship
    
      :param entities: a json string containing a list of identified entities 
    :type entities: str
    :param relationships: a list containing identified relationships to be evaluated 
    :type relationships: list
    :returns: a list of relationships involving entities that are definitely in the given list of identified entities
    :rtype: list
    """
    ent_list = json.loads(entities)["entities"]
    ent_set = set()
    for e in ent_list:
        ent_tuple = (e["entity_name"], e["pretty_label"])
        ent_set.add(ent_tuple)

    validated_entities_relations = []
    for rs in relationships:
        ent1 = (rs["source"], rs["source_pretty_label"])
        ent2 = (rs["target"], rs["target_pretty_label"])
        if ent1 not in ent_set or ent2 not in ent_set:
            continue
        else:
            validated_entities_relations.append(rs)   
    return validated_entities_relations


def validate_entities_types(relationships):
    """
    Ensures that the source and target entities' types match the stix objects involved 
    in each identified relationship, otherwise remove the relationship
    
    :param relationships: a list containing identified relationships to be evaluated
    :type relationships: list
    :returns: a list of relationships containing entities whose types have been validated
    :rtype: list
    """
    entity_types = {
        "Adversary: Actor" : ["intrusion-set"],
        "Capabilities: Malware" : ["malware"],
        "Capabilities: Malware Type" : ["malware"],
        "Capabilities: Tool" : ["tool"],
        "Capabilities: Vulnerability" : ["vulnerability"],
        "Victim: Country" : ["location"],
        "Victim: Region" : ["location"],
        "Victim: Sector" : ["identity"],
        "Victim: Name" : ["identity"],
        "Infra: Service" : ["infrastructure"],
        "Infra: Domain Name" : ["indicator", "domain-name"],
        "Capabilities: PDB Path" : ["indicator"],
        "Capabilities: File" : ["indicator", "file"],
        "Capabilities: SHA256 Hash" : ["indicator"],
        "Capabilities: SHA1 Hash" : ["indicator"],
        "Capabilities: MD5 Hash" : ["indicator"],
        "Capabilities: Directories" : ["indicator", "directory"],
        "Infra: URL" : ["indicator", "url"],
        "Infra: IPv4" : ["indicator", "ipv4-addr"],
        "Infra: IPv6" : ["indicator", "ipv6-addr"],
        "Infra: MAC Address" : ["indicator", "mac-addr"],
        "Infra: Email Address" : ["indicator", "email-addr"],
        "Metadata: Campaign" : ["campaign"]
    }

    validated_entities_relations = []
    for rs in relationships:
        source_obj = rs["relationship"].split()[0]
        target_obj = rs["relationship"].split()[2]

        if source_obj in entity_types[rs["source_pretty_label"]] and target_obj in entity_types[rs["target_pretty_label"]]: 
            validated_entities_relations.append(rs)
    
    return validated_entities_relations