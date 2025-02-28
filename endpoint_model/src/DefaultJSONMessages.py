#------------------------------------------------------------------------
# Simple Class for error and debugging purposes

class DefaultJSONMessages:
    def __init__(self):

        self.NO_JSON_BODY_400 = 'Invalid request. Post request must have JSON body.'
        self.REQ_PARAMS_400 = 'Invalid request. Required parameters not set.'
        self.BAD_PARAM_400 = 'Invalid request. Parameter value is invalid.'