# PneuNet

PneuNet is a full-stack **AI-powered pneumonia detection system** designed to analyze chest X-ray images and assist in identifying potential pneumonia cases using deep learning.

The system integrates **medical AI, secure client-server communication, and a modern desktop interface** to provide an end-to-end workflow for uploading medical images, performing inference on a trained neural network model, and returning diagnostic predictions.

PneuNet was built as a **complete production-style architecture**, demonstrating how AI models can be integrated into real-world software systems.

---

# Project Purpose

PneuNet was developed to demonstrate how artificial intelligence can be deployed within a secure software architecture to assist with medical image analysis.

### Automated Pneumonia Detection
Uses a trained deep learning model to classify chest X-ray images and estimate the probability of pneumonia.

### Secure Client–Server Communication
Ensures that medical images and sensitive data are transferred securely between the client application and the inference server.

### Medical AI Integration
Demonstrates how trained PyTorch models can be integrated into production systems.

### Diagnostic Assistance
Provides a prediction score to assist users in evaluating potential pneumonia cases.

---

# Features

## AI Inference Engine

The system includes a trained deep learning model capable of analyzing chest X-ray images.

Capabilities include:

- Pneumonia classification
- Probability scoring
- Fast inference
- Model loaded directly from `.pth` weights

The model processes images uploaded by the client and returns prediction results to the user interface.

---

## Secure Client–Server Architecture

PneuNet uses a custom networking layer built on top of TCP sockets.

Features include:

- JSON message protocol
- Secure message wrapper
- AES encrypted communication
- Client authentication system

The system uses two protocols:

### JsonProtocol
Handles basic structured message exchange between client and server.

### SecureJsonProtocol
Wraps the JSON protocol and encrypts messages using AES encryption after a secure handshake.

---

## Authentication System

The server includes a user authentication system.

Capabilities include:

- User registration
- Login authentication
- Email verification
- Two-factor authentication (OTP)
- Secure password hashing

Authentication ensures that only authorized users can upload medical images for analysis.

---

## Image Upload System

The client supports efficient image uploading.

Features include:

- Chunked file transfer
- Progress tracking
- Secure transmission
- File validation

Images are transmitted to the server where they are processed by the AI model.

---

## Graphical User Interface

The client application is built using **PySide6** and provides a modern desktop interface.

Views include:

- Login / Signup
- Dashboard
- Image Upload Panel
- Analysis Results
- Scan History

---

## Analysis Results

After an image is processed, the system returns:

- Pneumonia probability
- Confidence score
- Result classification

Results are displayed directly in the client dashboard.

---

# Communication Protocol

PneuNet uses a structured JSON protocol for communication.

Example request:


{"type": "PREDICT", "request_id": 7f3c2d4e-9a1b-4f2a-bc71-2e9c8a1d5f43}


Encrypted messages are wrapped using the SecureJsonProtocol layer.

---

## Installation

### Clone the repository

```bash
git clone https://github.com/eitanitzhakov/PneuNet.git
cd PneuNet
```

### Create a virtual environment

```bash
python -m venv venv
```

### Activate the environment

**Windows**

```bash
venv\Scripts\activate
```

**Linux / Mac**

```bash
source venv/bin/activate
```

### Install dependencies

```bash
pip install -r requirements.txt
```

---

## Running the Server

```bash
python Server/main.py
```

The server will start:

- Authentication service  
- AI inference engine  
- Database connection  

---

## Running the Client

```bash
python Client/main.py
```

The desktop interface will launch.

---
# Example Workflow

1. Launch the client application  
2. Register or log into an account  
3. Upload a chest X-ray image  
4. The image is securely transmitted to the server  
5. The AI model performs inference  
6. Prediction results are returned  
7. The client displays the pneumonia probability  

---

# Libraries Used

| Library | Purpose |
|-------|-------|
| PyTorch | Deep learning model inference |
| PySide6 | Desktop GUI framework |
| Socket | Client-server communication |
| SQLite | Database storage |
| Cryptography | Secure encryption |
| JSON | Structured message protocol |

---

# Disclaimer

PneuNet is an **academic and research project**.

It is **not approved for clinical use** and must not be used as a substitute for professional
