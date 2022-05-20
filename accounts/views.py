from base64 import urlsafe_b64decode
from email import message
from email.message import EmailMessage
from django.http import HttpResponse
from django.shortcuts import render , redirect

from carts.models import Cart, CartItem
from .models import Account
#from accounts.models import Account
from .forms import RegistrationForm
from django.contrib import messages, auth
from django.contrib.auth.decorators import login_required

#verification email
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import EmailMessage

from carts.views import _cart_id
from carts.models import Cart,CartItem


# Create your views here.
def register(request):
    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            first_name = form.cleaned_data['first_name']
            last_name = form.cleaned_data['last_name']
            phone_number = form.cleaned_data['phone_number']
            email = form.cleaned_data['email']
            password = form.cleaned_data['password']
            username = email.split("@")[0]
            user = Account.objects.create_user(first_name=first_name, last_name=last_name, email=email, username=username, password=password)
            user.phone_number = phone_number
            user.save()

            #USER Activation
            current_site = get_current_site(request)
            mail_subject = 'please activate your account'
            message = render_to_string('accounts/account_verification_email.html',{
                'user' : user,
                'domain' : current_site,
                'uid' : urlsafe_base64_encode(force_bytes(user.pk)),
                'token' : default_token_generator.make_token(user),
            })
            to_email = email
            send_email = EmailMessage(mail_subject, message, to=[to_email])
            send_email.send()
            messages.success(request, 'Thank you for registering with us. We have sent you a verification email to your email address [anandhu66330@gmail.com]. Please verify it.')
            return redirect('/accounts/login/?command=verification&email='+email)
    else:
        form = RegistrationForm()
    context = {
        'form' : form,
    }
    return render(request,'accounts/register.html', context)

def login(request):
    if request.method == 'POST':
        email = request.POST['email']
        password = request.POST['password']

        user = auth.authenticate(email=email, password= password)

        if user is not None:
            try:
               print('entering inside try block')
               cart = Cart.objects.get(cart_id=_cart_id(request))
               is_cart_item_exists = CartItem.objects.filter(Cart=cart).exists()
               print(is_cart_item_exists)
               if is_cart_item_exists:
                   cart_item = CartItem.objects.filter(Cart=cart)
                   print(cart_item)
                   

                   for item in cart_item:
                       item.user = user
                       item.save()
            except:
                print('entering iniside except block')
                pass
            auth.login(request, user)
            messages.success(request, 'you are now logged in.')
            return redirect('dashboard')
        else:
            messages.error(request, 'Invalid login credentials')
            return redirect('login')
    return render(request,'accounts/login.html')

# def login_otp(request):
#     if request.method=='POST':
#         mobile='7736441096'
#         mobile_number = request.POST['phone_number']
#         # if mobile==phone_number:
#         if Account.objects.filter(phone_number=mobile_number).exists():
#             user=Account.objects.get(phone_number=mobile_number)
#             # Your Account SID from twilio.com/console
#             account_sid = "ACc1160d4e274829b9628aa099d817661d"
#             # Your Auth Token from twilio.com/console
#             auth_token  = "3a6ce70fadb92b3e94660d4ea21eaa42"

#             client = Client(account_sid, auth_token)
#             global otp
#             otp = str(random.randint(1000,9999))
#             message = client.messages.create(
#                 to="+91".join(str(mobile_number)), 
#                 from_="+19207106849",
#                 body="Hello there! Your Login OTP is"+otp)
#             messages.success(request,'OTP has been sent to 7736441096 & enter OTP')
#             return render (request, 'accounts/login_otp1.html')

#         else:
#             messages.info(request,'The phone number is not registered')
#             return render (request, 'login_otp.html')
#     return render (request, 'accounts/login_otp.html')

# def login_otp1(request):
#     if request.method=='POST':
#         user = Account.objects.get(phone_number= 7736441096)
#         otpvalue = request.POST['otp']
#         if otpvalue == otp:
#             auth.login(request,user)
#             messages.success(request,'You are logged in')
#             return redirect('/')
#         else:   
#             messages.error(request,'Invalid OTP')
#             return redirect('login_otp1')
#     return render(request, 'accounts/login_otp1.html')


@login_required(login_url = 'login')
def logout(request):
    auth.logout(request)
    messages.success(request,'you are logged out.')
    return redirect('login')


def activate(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = Account._default_manager.get(pk=uid)
    except(TypeError, ValueError, OverflowError, Account.DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user,token):
        user.is_active = True
        user.save()
        messages.success(request,'congratulation! Your message is activated')
        return redirect('login')
    else:
        message.error(request, 'Invalid activation link')
        return redirect('register')


@login_required(login_url = 'login')
def dashboard(request):
    return render(request, 'accounts/dashboard.html')


def forgotPassword(request):
    if request.method == 'POST':
        email = request.POST['email']
        if Account.objects.filter(email=email).exists():
            user = Account.objects.get(email__exact=email)
            
            #Reset password email
            current_site = get_current_site(request)
            mail_subject = 'Reset your password'
            message = render_to_string('accounts/reset_password_email.html',{
                'user' : user,
                'domain' : current_site,
                'uid' : urlsafe_base64_encode(force_bytes(user.pk)),
                'token' : default_token_generator.make_token(user),
            })
            to_email = email
            send_email = EmailMessage(mail_subject, message, to=[to_email])
            send_email.send()

            messages.success(request, 'password reset email has been sent to your email address.')
            return redirect('login')
        else:
            messages.error(request, 'Account does not exist')
            return redirect('forgotPassword')
    return render(request, 'accounts/forgotPassword.html')

def resetpassword_validate(request, uidb64, token ):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = Account._default_manager.get(pk=uid)
    except(TypeError, ValueError, OverflowError, Account.DoesNotExist):
        user = None
    
    if user is not None and default_token_generator.check_token(user,token):
        request.session['uid'] = uid
        messages.success(request, 'please reset your password')
        return redirect('resetPassword')
    else:
        messages.error(request, 'this link has been expired')
        return redirect('login')

def resetPassword(request):
    if request.method == 'POST':
        password = request.POST['password']
        confirm_password = request.POST['confirm_password']

        if password == confirm_password:
            uid = request.session.get('uid')
            user = Account.objects.get(pk=uid)
            user.set_password(password)
            user.save()
            messages.success(request, 'Password reset successful')
            return redirect('login')
        else:
            messages.error(request, 'Password do not match!')
            return redirect('resetPassword')
    else:
        return render(request, 'accounts/resetPassword.html')
