from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from DataPreProcessor import DataPreProcessor
from DefaultJSONMessages import DefaultJSONMessages
from ClassifierModel import ReportClassifierModel
from NERModel import NERModel
from llmNER import LLMNER
from llmRE import LLMRE
from llmSUMMARY import LLMSUMMARY

#------------------------------------------------------------------------
# Create App

app = FastAPI()

#------------------------------------------------------------------------
# Create objects

default_msg = DefaultJSONMessages()
data_preprocessor = DataPreProcessor()
report_classifier_model = ReportClassifierModel("report_multi_v2", 0.7)
report_ner_model = NERModel("ner_v2")
llm_ner = LLMNER()
llm_re = LLMRE()
llm_summariser = LLMSUMMARY()

#------------------------------------------------------------------------
# API methods

# NLP method for sequence of NLP operations
@app.post("/nlp/model")
async def nlp_api(request: Request):
    """
    Args:
        request (Request): The incoming HTTP request containing JSON data with the following fields:
            - 'title' (str, optional): The title of the post.
            - 'content' (str, optional): The content of the post.
            - 'lang' (str, optional): The language of the post in ISO 639‑1 Code (2-char string).
            - 'models' (list of str): The list of NLP models to apply.
        JSONResponse: A JSON object containing:
            - 'title' (str): The original title.
            - 'content' (str): The original content.
            - 'translated_title' (str, optional): The translated title if applicable.
            - 'translated_content' (str, optional): The translated content if applicable.
            - 'nlp' (dict): A dictionary with results from the specified NLP models.
        - 'report_classifier': Classifies the report.
        - 'report_ner': Named Entity Recognition using a report NER model.
        - 'llm_ner': Validates NER results using a large language model.
        - 'llm_re': Extracts relationships using a large language model.
        - 'llm_summariser': Summarizes the content using a large language model.
        - 400: If the request body is missing or required parameters are not provided.
    """
    
    # CONSTANTS
    doc_char_limit = 5000

    args = await request.json()
    print(args)
    if not args:
        raise HTTPException(status_code=400, detail=default_msg.NO_JSON_BODY_400)

    title = args.get('title')
    content = args.get('content')
    lang = args.get('lang')
    models = args.get('models')

    # Convert content into empty string if it is null
    if not content:
        content = ""

    # Check all required arguments exist
    if not models:
        raise HTTPException(status_code=400, detail=default_msg.REQ_PARAMS_400)

    # Create pre-processing pipes
    pipes = []
    if lang != "en":
        pipes.append(["translator", "html_remover", "illegal_char_remover"])
    else:
        pipes.append(["html_remover", "illegal_char_remover"])
    # If running NER
    if "post_ner" in models:
        pipes.append(["url_remover", "consec_newline_remover"])

    # Pre-process title
    if title and title != "":
        preprocessed_title_doc = data_preprocessor.preprocess(title, pipes)
        preprocessed_title = preprocessed_title_doc["pipe_outputs"]
    else:
        preprocessed_title_doc = {}
        preprocessed_title = None

    # Pre-process content
    preprocessed_content_doc = data_preprocessor.preprocess(content, pipes)
    preprocessed_content = preprocessed_content_doc["pipe_outputs"]

    # Create output doc
    doc = {
        "title": title,
        "content": content,
        "translated_title": preprocessed_title_doc.get("translated"),
        "translated_content": preprocessed_content_doc.get("translated")
    }

    # Get NLP outputs
    accepted_models = ["report_classifier", "report_ner", "llm_ner", "llm_re", "llm_summariser"]
    nlp_results = {}

    for model in models:
        if model in accepted_models:

            ### REPORT CLASS MODEL ###
            if model == "report_classifier":
                nlp_results[model] = report_classifier_model.get_final_labels(preprocessed_title[0], preprocessed_content[0][:doc_char_limit])

            ### REPORT NER MODEL ###
            elif model == "report_ner":
                # Only do the ner if the post has been translated successfully to english, or if it was originally english
                if lang == 'en' or (doc.get("translated_title") or doc.get("translated_content")):
                    nlp_results["spacyNER"] = report_ner_model.getEntities(preprocessed_title[0], preprocessed_content[0])
                else:
                    nlp_results[model] = []

            elif model == "llm_ner" and "report_ner" in models:
                txt = preprocessed_title[0] + " " + preprocessed_content[0]
                entities = nlp_results.get("spacyNER")
                nlp_results["validatedNER"] = llm_ner.run_llm_NER(txt, entities, preprocessed_title[0])

            elif model == "llm_re" and "report_ner" in models:
                txt = preprocessed_title[0] + " " + preprocessed_content[0]
                nlp_results[model] = llm_re.run_llm_RE(txt, nlp_results, preprocessed_title[0])

            elif model == "llm_summariser":
                txt = preprocessed_title[0] + " " + preprocessed_content[0]
                nlp_results[model] = llm_summariser.apply_inference(txt)

    doc["nlp"] = nlp_results

    return JSONResponse(content=doc)


