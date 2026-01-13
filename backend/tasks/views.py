from rest_framework import viewsets
from rest_framework.permissions import IsAuthenticated

from .models import Task
from .serializers import TaskSerializer


class TaskViewSet(viewsets.ModelViewSet):
    serializer_class = TaskSerializer
    permission_classes = [IsAuthenticated]
    filterset_fields = ["status"]        # GET /api/tasks/?status=pending
    ordering_fields = ["due_date", "created_at"]
    ordering = ["due_date", "-created_at"]

    def get_queryset(self):
        # user-specific tasks only
        return Task.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)
