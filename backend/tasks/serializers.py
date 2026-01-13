from rest_framework import serializers
from .models import Task


class TaskSerializer(serializers.ModelSerializer):
    created_at = serializers.DateTimeField(read_only=True)

    class Meta:
        model = Task
        fields = ["id", "title", "description", "status", "due_date", "created_at"]

    def validate_title(self, value: str) -> str:
        value = (value or "").strip()
        if not value:
            raise serializers.ValidationError("Title cannot be empty.")
        return value
