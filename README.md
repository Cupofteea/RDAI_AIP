# RDAI-AIP Project

The aim of this project is to showcase deployment of AI work. Ideally, it would have to consists of:
- An AI model
- FastAPI + link to backend
- Dockers for deployment

In this project, I am going to create a Natural Language Processing (NLP) Pipeline that enriches cyber related articles from Open Source Intelligence. 

The NLP pipeline will consists of:
1. Preprocessing steps (translation to English using deeptranslator)
2. Multi-label Classifier (A custom trained model that contains cyber labels such as MALWARE, APT, FINANCIAL MOTIVATION, etc)
3. Named Entity Recognition  (A custom trained model to pick out cyber related entities such as Adversary/Victim countries, etc. These entities are further validated via an AWS Claude LLM)
4. Summariser (AWS Claude LLM)

To deploy this pipeline, we will be using dockers.

There are 2 additional files (`sample_input.txt` and `sample_output.txt`) which shows the sample input and output response of the pipeline


## API
**POST** /nlp/model - TO RUN NLP VIA MODELS

|Parameters | Type | Details|
|--|--|--|
|title|str|Title of the news report|
|content|str|Content of the news report|
|lang|str|ISO 639‑1 Code|
|models|['str']|Accepted models are: `report_classifier`, `report_ner`, `llm_ner`, `llm_re`, `llm_summariser`|

**Sample Python Request**
    
    title = "This is a fake title"
    content = "This is a fake content"
    lang = "en"
    models = ["report_classifier", "report_ner", "llm_ner", "llm_re", "llm_summariser"]

    url = "http://<INSERT IP>:<INSERT PORT>/nlp/model"

    raw_data = {
        "title": title,
        "content": content,
        "lang": lang,
        "models": models
    }

    res = request.post(url, json=raw_data) 

**Sample Output**

    {
    "content": 'This is a fake content',
    "nlp": {
        "llm_re": {
            "model": <LLM That is used>,
            "relations": [
                {
                    "relationship": "malware targets identity",
                    "source": "Banshee Stealer",
                    "source_pretty_label": "Capabilities: Malware",
                    "target": "cryptocurrency",
                    "target_pretty_label": "Victim: Sector",
                },
                ...
            ],
            "tokens_used": {
                "input_tokens": XXX,
                "output_tokens": XXX,
                "total_tokens": XXX,
            },
        },
        "report_classifier": [
            "CYBERCRIMINAL",
            "DATA EXFIL",
            "FINANCIAL MOTIVATION",
            "MALWARE, TOOLS & EXPLOITS",
            "PHISHING",
            "TARGETED IT",
            "TARGETED TECH ENTERPRISE",
        ],
        "spacyNER": [
            {
                "end_char": 19,
                "label": "C_MALWARE",
                "occurrence": 0,
                "pretty_label": "Capabilities: Malware",
                "start_char": 4,
                "tag_index": 0,
                "text": "Banshee Stealer",
            },
            ...
        ],
        "validatedNER": {
            "classifyTA_model": LLM Used,
            "classifyTA_tokens_used": {
                "input_tokens": XXX,
                "output_tokens": XXX,
                "total_tokens": XXX,
            },
            "entities": [
                {
                    "label": "C_MALWARE",
                    "pretty_label": "Capabilities: Malware",
                    "text": "Banshee Stealer",
                },
                ...
                
            ],
            "validation_model": <LLM Used>,
            "validation_tokens_used": {
                "input_tokens": XXX,
                "output_tokens": XXX,
                "total_tokens": XXX,
            },
            "llm_summariser": {
                "model": <LLM Used>,
                "summary": <Summarised text>,
                "finish_reason": <Reason why llm stopped processing>,
                "tokens_used": {
                    "input_tokens": XXX,
                    "output_tokens": XXX,
                    "total_tokens": XXX
                }
            }
        },
    },
    "title": "This is a fake title",
    "translated_content": None,
    "translated_title": None,
    }


## Deploy (For local testing)
1. Download necessary packages: `pip install -r requirements.txt`
2. Install spacy en_core_web_sm `python -m spacy download en_core_web_sm` and spacy-transformers `python -m spacy download en_core_web_trf`
3. Get the NER and Multi-Label model from Sebastian or in the google drive. Placed these models in the following directory `./endpoint_model/nlp_models/<INSERT AI MODEL>`
4. Create and fill in `config.yml` based on `config.yml.copy`
5. Run `fastapi dev nlp_api_endpoint.py` *endpoint_model*.

## Deploy (Prod)

Deployment of nlp endpoints are done using dockers

### **On Development Computer (Prod Branch)**

### Step A: Build docker images

1. Make sure you are in the same directory as the dockerfile for this project
2. Build image for labels (via MODEL): `sudo docker build -t labels_model -f endpoint_model/Dockerfile .`

### Step B: Transfer of files
1. Save the docker images into tar files using `docker save -o <image_name>.tar <image_name>`
2. Transfer the files over using `scp` if deploying via cloud or relevant ways necessary.

### Step C: Run the containers
1. Run labels (via MODEL): `sudo docker run --detach --publish 8000:8000 --name nlp_report_pipeline nlp_report_pipeline`


