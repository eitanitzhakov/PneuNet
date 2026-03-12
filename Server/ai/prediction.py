import os
import time
from typing import Dict, Any, Optional

import timm
import torch
from PIL import Image
from torchvision import transforms


class Predictor:
    def __init__(
        self,
        weights_path: str,
        arch: str = "tf_efficientnet_b4_ns",
        img_size: int = 380,
        device: Optional[str] = None,
        threshold: float = 0.5,
    ):
        if device is None:
            device = "cuda" if torch.cuda.is_available() else "cpu"
        self.device = torch.device(device)
        self.threshold = float(threshold)

        self.model = timm.create_model(
            arch,
            pretrained=False,
            num_classes=1
        ).to(self.device).eval()

        state = torch.load(weights_path, map_location=self.device)
        if isinstance(state, dict) and "state_dict" in state:
            state = state["state_dict"]

        if isinstance(state, dict):
            state = {k.replace("module.", ""): v for k, v in state.items()}

        missing, unexpected = self.model.load_state_dict(state, strict=True)
        if missing or unexpected:
            raise RuntimeError(
                f"State_dict mismatch. missing={len(missing)} unexpected={len(unexpected)}"
            )

        self.tf = transforms.Compose([
            transforms.Resize((img_size, img_size)),
            transforms.ToTensor(),
            transforms.Normalize(
                [0.485, 0.456, 0.406],
                [0.229, 0.224, 0.225],
            ),
        ])

        self.supported_exts = {".jpg", ".jpeg", ".png", ".bmp", ".webp"}

    @torch.no_grad()
    def predict(self, path: str) -> Dict[str, Any]:
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
        ext = os.path.splitext(path)[1].lower()
        if ext not in self.supported_exts:
            raise ValueError(
                f"Unsupported file format: {ext}. "
                f"Supported formats: {', '.join(sorted(self.supported_exts))}"
            )
        return Image.open(path).convert("RGB")