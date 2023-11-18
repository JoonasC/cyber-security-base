from django.contrib.auth import views as auth_views
from django.urls import path

from . import views

urlpatterns = [
    path('', views.index_view, name='index'),
    path('send_message/', views.send_message_view, name='send_message'),
    path('delete_message/<int:message_id>/', views.delete_message_view, name='delete_message'),
    path('login/', auth_views.LoginView.as_view(template_name='login.html', redirect_authenticated_user=True),
         name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('register/', views.register_view, name='register'),
]
