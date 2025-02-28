import spacy
import re

from bs4 import BeautifulSoup
from deep_translator import GoogleTranslator

#------------------------------------------------------------------------
# Common classes and functions  
# Mainly for preprocessing raw texts

class DataPreProcessor():
    def __init__(self):
        self.translator = GoogleTranslator(source='auto', target='en')
        self.spacy_nlp = spacy.load("en_core_web_sm")

    def html_remover(self, doc):
        """
        Removes html tags in a given text
        Input: doc
        Output: doc
        """
        txt = doc["pipe_text"]
        #txt = txt.replace("\n","")
        soup=BeautifulSoup(txt,'html.parser')
        a=soup.get_text()
        #doc["non_html_sentence"] = a
        doc["pipe_text"] = a
        return doc

    # char limit 5000 currently 100000

    def illegal_char_remover(self, doc):
        """
        Removes some illegal characters that are not in unicode (represented in hex or bytes).
        """
        txt = doc["pipe_text"]
        txt_encoded = txt.encode("unicode_escape")
        txt_encoded_cleaned = re.sub(b'\\\\x[a-f0-9][a-f0-9]', b'', txt_encoded)
        txt_cleaned = txt_encoded_cleaned.decode("unicode_escape")
        doc["pipe_text"] = txt_cleaned
        return doc
    

    def url_remover(self, doc):
        """
        Removes URLs from text
        """
        txt = doc["pipe_text"]
        url_regex = r'\[?\(?(?:http|ftp|https):\/\/(?:www.)?([\w_-]+(?:(?:\.[\w_-]+)+))(?:[\w.,@?^=%&:\/~+#-]*[\w@?^=%&\/~+#-])\]?\)?'
        txt_cleaned = re.sub(url_regex, "", txt)
        doc["pipe_text"] = txt_cleaned
        return doc


    def consec_newline_remover(self, doc):
        """
        Removes consecutive newlines (3 or more) from text
        """
        txt = doc["pipe_text"]
        consec_newline_regex = r'\n{3,}'
        txt_cleaned = re.sub(consec_newline_regex, "\n\n", txt)
        doc["pipe_text"] = txt_cleaned
        return doc
    

    def split_sentences(self, doc):
        """
        Can only deal with one string (not a list)
        """
        # Tried Spacy sentencizer
        spacy_doc = self.spacy_nlp(doc["pipe_text"])
        sentences = [sent.text.strip() for sent in spacy_doc.sents if len(sent.text.strip()) > 0]
        
        doc["sents"] = sentences

        return doc

    def translate(self, doc, char_limit=50000, translation_chunk_size=2000):
        """
        Can only deal with one string (not a list)
        """

        # Limit the translation to 50000 chars. If larger, dont translate.
        if len(doc["pipe_text"]) <= char_limit:

            # Split text into chunks that the translation engine can handle. We limit this to 2000 char as of now
            lines = doc["pipe_text"].split("\n")
            chunks = []
            char_count = 0
            temp_chunk = []
            for line in lines:
                char_count += (len(line) + 1)

                if char_count <= translation_chunk_size:
                    temp_chunk.append(line)
                    char_count += len(line) + 1
                else:
                    chunks.append("\n".join(temp_chunk))
                    char_count = len(line)
                    temp_chunk = [line]

            if len(temp_chunk) > 0:
                chunks.append("\n".join(temp_chunk))

            new_pipe_text = []
            for text in chunks:
                if len(text) > translation_chunk_size:
                    translated_text = text
                else:
                    translated_text = self.translator.translate(text)
                    if not translated_text:
                        translated_text = ''
                new_pipe_text.append(translated_text)

            full_translated = '\n'.join(new_pipe_text)
            doc["translated"] = full_translated
            doc["pipe_text"] = full_translated

        return doc
    

    def preprocess(self, text, pipes, doc_char_limit=5000):
        """
        The returned doc might have the following fields, depending on the pipes
        - original_text
        - translated
        - sents
        - pipes is a list of lists of various pipe components 
            E.g. [[html_remover, illegal_char_remover, translator], [url_remover, consec_newline_remover]]
        """

        # Limit the number of characters if not there will be a memory error
        doc = {
            "original_text": text,
            "pipe_text": text,
            "pipe_outputs": []
        }

        # Sentencizer has to be the last pipe.
        pipe_component_to_func = {
            "html_remover": self.html_remover,
            "illegal_char_remover": self.illegal_char_remover,
            "translator": self.translate,
            "url_remover": self.url_remover,
            "consec_newline_remover": self.consec_newline_remover
        }

        for pipe in pipes:
            for pipe_component in pipe:
                doc = pipe_component_to_func[pipe_component](doc)

            # Truncate pipe text and then do the remaining operations
            doc["pipe_outputs"].append(doc["pipe_text"])

        doc.pop("pipe_text")

        return doc