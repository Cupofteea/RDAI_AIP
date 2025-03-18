FROM python:3.9

COPY nlp_reports/endpoint_model/src /opt/endpoint_model

# install requirements
WORKDIR /opt
RUN pip install --no-cache-dir -r endpoint_model/requirements.txt && \
    python -m spacy download en_core_web_sm && \
    python -m spacy download en_core_web_trf
    
# start nlp endpoint
WORKDIR /opt/endpoint_model
CMD ["fastapi", "run", "--workers", "4","nlp_api_endpoint.py"]
