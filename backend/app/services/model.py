"""
Multi-Task Learning Model (MTL_MLP)
Based on Web3-Scamming-Attack-Detection/Deploy/api/model.py
"""
import torch
import torch.nn as nn


class SHAPModelWrapper(nn.Module):
    """Wrap MTL_MLP to expose a single-task forward(x) for SHAP DeepExplainer."""
    def __init__(self, model: nn.Module, task_id: str):
        super().__init__()
        self.model = model
        self.task_id = task_id
        self.model.eval()

    def forward(self, x):
        # delegate to underlying model with task_id
        return self.model(x, task_id=self.task_id)


class MTL_MLP(nn.Module):
    def __init__(self, input_dim=15, shared_dim=128, head_hidden_dim=64):
        super(MTL_MLP, self).__init__()
        # Shared Backbone
        self.shared_backbone = nn.Sequential(
            nn.Linear(input_dim, shared_dim),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(shared_dim, shared_dim),
            nn.ReLU(),
            nn.Dropout(0.3)
        )
        
        # Task 1 Head (Transaction Phishing) - returns logits
        self.task1_head = nn.Sequential(
            nn.Linear(shared_dim, head_hidden_dim),
            nn.ReLU(),
            nn.Linear(head_hidden_dim, 1) # Output logits
        )
        
        # Task 2 Head (Account Phishing) - returns logits
        self.task2_head = nn.Sequential(
            nn.Linear(shared_dim, head_hidden_dim),
            nn.ReLU(),
            nn.Linear(head_hidden_dim, 1) # Output logits
        )

    def forward(self, x, task_id):
        # x: (B, input_dim)
        shared_output = self.shared_backbone(x)
        if task_id == 'transaction':
            return self.task1_head(shared_output)
        elif task_id == 'account':
            return self.task2_head(shared_output)
        else:
            raise ValueError(f"Unknown task_id: {task_id}")

