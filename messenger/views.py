from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib.auth.views import logout_then_login
from django.db import transaction
from django.shortcuts import render, redirect
from django.urls import reverse

from .models import Message


@login_required
def index_view(request):
    received_messages = Message.objects.filter(sent_to=request.user)
    sent_messages = Message.objects.filter(sent_by=request.user)

    return render(request, 'index.html', {'received_messages': received_messages, 'sent_messages': sent_messages})


@login_required
@transaction.atomic
def send_message_view(request):
    received_messages = Message.objects.filter(sent_to=request.user)
    sent_messages = Message.objects.filter(sent_by=request.user)

    if request.method == 'POST':
        recipient_username = request.POST.get('recipient_username')
        text = request.POST.get('text')

        if recipient_username == '' or text == '':
            return render(request, 'index.html',
                          {'received_messages': received_messages, 'sent_messages': sent_messages,
                           'error': 'The recipient or message text was missing'})
        if recipient_username == request.user.username:
            return render(request, 'index.html',
                          {'received_messages': received_messages, 'sent_messages': sent_messages,
                           'error': 'Cannot send a message to self'})
        try:
            recipient = User.objects.get(username=recipient_username)
        except User.DoesNotExist:
            return render(request, 'index.html',
                          {'received_messages': received_messages, 'sent_messages': sent_messages,
                           'error': 'A user with the username {} does not exist'.format(recipient_username)})

        message = Message(sent_by=request.user, sent_to=recipient, text=text)
        message.save()

    return render(request, 'index.html', {'received_messages': received_messages, 'sent_messages': sent_messages})


@login_required
@transaction.atomic
def delete_message_view(request, message_id):
    """
    This function has two security flaws:
    1. Broken access control
    This function does not check whether a user that is trying to delete a message is the author of the message they are
    trying to delete. This can be fixed by checking whether the sent_by field of the message is equal to the value of the
    request.user variable, and showing an error if not.
    For example:
    if message.sent_by != request.user:
        return render(request, 'index.html', ... 'error': 'Cannot delete a message sent by another user'})

    2. CSRF
    This function can be called with a GET request and there is no CSRF token check, which means that a third party site
    can embed an image tag such as <img src="http://some.address/messenger/delete_message/<some_id>"> and delete messages
    as the logged-in user. This can be fixed by checking whether the request method is POST, which will automatically
    cause Django to require a CSRF token.
    For example:
    if request.method == 'POST':
        # Code that deletes the message goes here
    """
    received_messages = Message.objects.filter(sent_to=request.user)
    sent_messages = Message.objects.filter(sent_by=request.user)

    try:
        message = Message.objects.get(pk=message_id)
    except Message.DoesNotExist:
        return render(request, 'index.html', {'received_messages': received_messages, 'sent_messages': sent_messages,
                                              'error': 'A message with the id {} does not exist'.format(message_id)})

    message.delete()
    return render(request, 'index.html', {'received_messages': received_messages, 'sent_messages': sent_messages})


@login_required
def logout_view(request):
    return logout_then_login(request, reverse('login'))


@transaction.atomic
def register_view(request):
    if request.user.is_authenticated:
        return redirect('index')

    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        email = request.POST.get('email')

        if username == '' or password == '' or email == '':
            return render(request, 'register.html', {'error': 'The username, password or email was missing'})
        if User.objects.filter(username=username).count() > 0:
            return render(request, 'register.html', {'error': 'This username is already taken'})

        User.objects.create_user(username, email, password)
        return redirect('login')

    return render(request, 'register.html')
