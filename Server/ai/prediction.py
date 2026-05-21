import os
import time
from typing import Dict, Any, Optional

import timm
import torch
from PIL import Image
from torchvision import transforms


class Predictor:
    """
    PyTorch-based neural network wrapper for pneumonia detection in
    chest X-ray images.

    Loads a pre-trained EfficientNet model and performs inference
    on medical images after preprocessing. Outputs binary classification
    (PNEUMONIA vs NORMAL) with confidence score.

    Purpose:
        Encapsulate all model loading, preprocessing, and inference
        logic for medical image analysis in PneuNet.

    Model:
        - Architecture: EfficientNet-B4 (tf_efficientnet_b4_ns)
        - Pretrained: Loaded from .pth weights file
        - Output: Single logit passed through sigmoid for probability
        - Inference Time: Typically 100-500ms on CPU/GPU

    Preprocessing:
        - Resize to (img_size, img_size)
        - Convert to RGB (handles grayscale)
        - ImageNet normalization (mean=[0.485, 0.456, 0.406],
          std=[0.229, 0.224, 0.225])

    Device Support:
        - Auto-detects CUDA if available, falls back to CPU
        - Can be forced to specific device

    Attributes:
        device (torch.device): Computation device (cuda/cpu).
        model (nn.Module): Loaded PyTorch model.
        threshold (float): Classification threshold (default 0.5).
        tf (transforms.Compose): Image preprocessing pipeline.
        supported_exts (set): Supported image formats.
    """

    def __init__(
        self,
        weights_path: str,
        arch: str = "tf_efficientnet_b4_ns",
        img_size: int = 380,
        device: Optional[str] = None,
        threshold: float = 0.5,
    ):
        """
        Initialize predictor by loading model weights and building pipeline.

        Args:
            weights_path (str): Path to .pth weights file.
            arch (str): Model architecture name (timm compatible).
            img_size (int): Input image size in pixels (default 380).
            device (Optional[str]): 'cuda', 'cpu', or None for auto.
            threshold (float): Classification threshold (default 0.5).

        Raises:
            RuntimeError: If weights file not found or state_dict incompatible.
        """
        if device is None:
            device = "cuda" if torch.cuda.is_available() else "cpu"
        self.device = torch.device(device)
        self.threshold = float(threshold)

        self.model = (
            timm.create_model(arch, pretrained=False, num_classes=1)
            .to(self.device)
            .eval()
        )

        state = torch.load(weights_path, map_location=self.device)
        if isinstance(state, dict) and "state_dict" in state:
            state = state["state_dict"]

        if isinstance(state, dict):
            state = {k.replace("module.", ""): v for k, v in state.items()}

        missing, unexpected = self.model.load_state_dict(state, strict=True)
        if missing or unexpected:
            raise RuntimeError(
                f"State_dict mismatch. missing={len(missing)} unexpected={
                    len(unexpected)
                }"
            )

        self.tf = transforms.Compose(
            [
                transforms.Resize((img_size, img_size)),
                transforms.ToTensor(),
                transforms.Normalize(
                    [0.485, 0.456, 0.406],
                    [0.229, 0.224, 0.225],
                ),
            ]
        )

        self.supported_exts = {".jpg", ".jpeg", ".png", ".bmp", ".webp"}

    @torch.no_grad()
    def predict(self, path: str) -> Dict[str, Any]:
        """
        Run inference on a medical image and return results.

        Loads image, preprocesses, runs through model, and applies
        sigmoid to convert logit to probability. Classification
        determined by threshold comparison.

        Args:
            path (str): Path to image file (supported formats: .jpg,
                .jpeg, .png, .bmp, .webp).

        Returns:
            dict: Prediction results including:
                - prob: float (0.0 to 1.0) sigmoid probability
                - label: str ("PNEUMONIA" or "NORMAL")
                - threshold: float (classification threshold used)
                - latency_ms: int (inference time in milliseconds)

        Raises:
            ValueError: If image format not supported.
            RuntimeError: If model fails during inference.
        """
        t0 = time.perf_counter()

        img = self._load_as_pil_rgb(path)
        x = self.tf(img).unsqueeze(0).to(self.device)

        y = self.model(x)
        logit = y.float().view(-1)[0]
        prob = torch.sigmoid(logit).item()

        latency_ms = int((time.perf_counter() - t0) * 1000)
        label = "PNEUMONIA" if prob >= self.threshold else "NORMAL"

        return {
            "prob": float(prob),
            "label": label,
            "threshold": self.threshold,
            "latency_ms": latency_ms,
        }

    def _load_as_pil_rgb(self, path: str) -> Image.Image:
        """
        Load image file and convert to RGB.

        Handles grayscale images by converting to RGB. Raises error
        for unsupported formats.

        Args:
            path (str): Path to image file.

        Returns:
            Image.Image: PIL Image in RGB mode.

        Raises:
            ValueError: If file extension not in supported_exts.
        """
        ext = os.path.splitext(path)[1].lower()
        if ext not in self.supported_exts:
            raise ValueError(
                f"Unsupported file format: {ext}. "
                f"Supported formats: {', '.join(sorted(self.supported_exts))}"
            )
        return Image.open(path).convert("RGB")
