from rest_framework.views import APIView
from django.http import JsonResponse
import json
from .phishing_url_detection import DETECTION
import numpy as np
import pickle
import warnings

class URLPredictionApiView(APIView):
	
    def post(self, request):
        js = str(request.data).replace("'", '"')
        # GET THE URL FROM THE API
        url = (json.loads(js)['url'])
        detection = DETECTION()
        # CALL THE DECTECTION METHOD HERE
        prediction = detection.feature_extractions(url)
        print(prediction)

        # Convert features to numpy array and reshape if necessary
        features = np.array(prediction[1:]).reshape(1, -1)

        # Assuming `features` is in a format that the model expects
        with open('RandomForest.pickle.dat', 'rb') as model_file:
            model = pickle.load(model_file)
            # Suppress the warning
            with warnings.catch_warnings():
                warnings.simplefilter('ignore')
                model_prediction = model.predict(features)[0]

        # Convert prediction to a native Python data type
        model_prediction = int(model_prediction)
        # print(model_prediction)
        return JsonResponse({"success": True, "detection": prediction}, safe=False)
