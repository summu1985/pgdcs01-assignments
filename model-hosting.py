import joblib
from fastapi import FastAPI
from pydantic import BaseModel
import numpy as np
import pickle

app = FastAPI()

# Load the trained model
#model = joblib.load('xgb_model.pkl')
model = pickle.load(open("XGBoostClassifier.pickle.dat", "rb"))

class Features(BaseModel):
    features: list

@app.post('/predict')
def predict(data: Features):
    X = np.array(data.features)

    # Make predictions using the loaded model
    y_pred_proba = model.predict_proba(X)
    y_pred = model.predict(X)

    # Return the predictions as a JSON response
    response = {
        'probabilities': y_pred_proba.tolist(),
        'predictions': y_pred.tolist()
    }
    return response

if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host='0.0.0.0', port=8000)
