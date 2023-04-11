from django.conf import settings
import random, datetime, pytz
from rest_framework.viewsets import ModelViewSet
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.authtoken.models import Token
from django.contrib.auth import logout
from user.models import *
from user.serializers import *
from .jwt_auth import get_tokens_for_user



def get_random_number_4d():
    return random.randint(1111,9999)


def send_email_verification_otp(request, user):
    otp = get_random_number_4d()
    user.otp = otp
    user.save()
    send_mail(
        subject="Account Verification Otp",
        message = "Your Email Verification OTP is : %d " %otp ,
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[user.email],
        fail_silently=False
    )
    return True


@api_view(['POST'])
def re_send_email_verification_otp(request):
    try:
        email = request.data['email'].lower()
        user = CustomUser.objects.get(email=email)
        if send_email_verification_otp(request, user):
            return Response({'message':"Sent..."}, status=200)
    except Exception as e:
        return Response({'message':"{}".format(e)}, status=400)


@api_view(['POST'])
def verify_email(request):
    email = request.data['email'].lower()
    otp = request.data['otp']
    try:
        user = CustomUser.objects.get(email=email)
        if not user.is_active:
            # pre_10_min = pytz.UTC.localize(datetime.datetime.now() - datetime.timedelta(hours=5, minutes=40))
            pre_1_day = pytz.UTC.localize(datetime.datetime.now() - datetime.timedelta(days=1))
            if user.otp == otp:
                if user.updated_at > pre_1_day:
                    user.is_active = True
                    user.otp = ""
                    user.save()
                    token = Token.objects.get_or_create(user=user)[0]
                    return Response({'message':"Verified..! You can login now.", 'token':f'{token}'})
                return Response({'message': 'otp expired...'}, status=400)
            return Response({'message': 'invalied otp...'}, status=400)
        return Response({"message":"Your email is already verified.."})
    except Exception as e:
        return Response({"message":"{}".format(e)}, status=400)



class UserViewSet(ModelViewSet):
    
    queryset = CustomUser.objects.all()
    serializer_class = UserSerializer
    
    '''SignUp user'''
    def create(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            serializer.save()
            response = {
                "status": status.HTTP_201_CREATED,
                "message": "Success",
            }
            try:
                # sending otp to mail
                email = request.data['email'].lower()
                user = CustomUser.objects.get(email=email)
                send_email_verification_otp(request, user)
            except:
                response['error_message'] = "Unable send mail"
            return Response(data=response, status=201)
        response = {
            'status': status.HTTP_400_BAD_REQUEST,
            'message': "Bad Request",
            'data': serializer.errors
        }
        return Response(data = response, status = 400)
        
    # return logged user information
    def list(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            return Response(UserSerializer(CustomUser.objects.get(id=request.user.id)).data)
        return Response(status=401)
    
    def destroy(self, request, *args, **kwargs):
        return Response(status=401)
    
    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        self.serializer_class = UserUpdateSerializer
        if request.user.is_authenticated and instance.id == request.user.id:
            pass
        else:
            return Response(status=401)
        return super().update(request, *args, **kwargs)
    

@api_view(['POST'])
def user_login(request):
    '''login user api view'''
    serializer = UserLoginSerializer(data=request.data)
    if serializer.is_valid():
        try:
            email = serializer.validated_data['email'].lower()
            password = serializer.validated_data['password']
            user = CustomUser.objects.get(email=email)
            if user.check_password(password):
                if user.is_active:
                    token = get_tokens_for_user(user)
                    user.save()
                    return Response({'auth_token': token, 'status': status.HTTP_200_OK})
                else:
                    return Response({'message': "User not active...", 'status': status.HTTP_401_UNAUTHORIZED}, status=401)
            else:
                return Response({'message': "Invailid password...", 'status': status.HTTP_401_UNAUTHORIZED}, status=401)
        except CustomUser.DoesNotExist:
            return Response({'message': "User not found.", 'status': status.HTTP_404_NOT_FOUND}, status=404)
        except Exception as e:
            return Response({'message':f"{e}.", 'status': status.HTTP_400_BAD_REQUEST}, status=400)
    response = {
        "status": status.HTTP_400_BAD_REQUEST,
        "message": "Bad request.",
        "data": serializer.errors
    }
    return Response(data = response, status=400)
    

@api_view(['POST'])
def forget_password(request):
    try:
        email = request.data['email'].lower()
        user = CustomUser.objects.get(email=email)
        otp = get_random_number_4d()
        user.otp = otp
        user.save()
        email = send_mail(
            subject="Forget Password Otp - Mother Dairy",
            message="Your Otp is {} valied up to 10 min".format(otp),
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            fail_silently=False
        )
        return Response({'message':"otp sent valied upto 10 min", 'status': status.HTTP_200_OK}, status=200)
    except CustomUser.DoesNotExist:
        return Response({'message':"User not found...", 'status': status.HTTP_404_NOT_FOUND}, status=404)
    except Exception as e:
        return Response({'message':f"bad requet.", "data": f"{e}", 'status': status.HTTP_400_BAD_REQUEST}, status=400)
    

@api_view(['POST'])
def forget_password_confirm(request):
    email = request.data['email'].lower()
    otp = request.data['otp']
    new_password = request.data['new_password']
    re_new_password = request.data['re_new_password']
    if new_password != re_new_password:
        return Response({'message': 'Confirm Password not matched..'})
    else:
        password = new_password
    try:
        user = CustomUser.objects.get(email=email)
        pre_10_min = pytz.UTC.localize(datetime.datetime.now() - datetime.timedelta(hours=5, minutes=40))
        if user.otp == otp:
            if user.updated_at > pre_10_min:
                user.password = password
                user.otp = ""
                user.save()
                return Response({'message':"saved.."}, status=200)
            return Response({'message': 'otp expired...'})
        return Response({'message': 'invalied otp...'})
    except CustomUser.DoesNotExist:
        return Response({'message':"User not found..."})
    except Exception as e:
        return Response({'message':"{}".format(e)})

    
@api_view(['POST'])
def change_password(request):
    user = request.user
    old_password = request.data.get('password')
    new_password = request.data.get('new_password')
    re_new_password = request.data.get('re_new_password')
    if user.is_authenticated and user.check_password(old_password):
        if new_password == re_new_password:
            user.password = new_password
            user.save()
            return Response(data={"message":"Password changed success."}, status=200)
        else:
            return Response(data={"message":"Please use strong Password (Capital, small, special charector and numbers) Min 6 digits"}, status=400)
    else:
        return Response(data={"message":"Invailid creadentials."}, status=400)


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def user_logout(request):
    request.user.auth_token.delete()
    logout(request)
    return Response({'message':'User Logged out successfully'})


