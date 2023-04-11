from django.contrib.auth import login, logout
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .models import CustomUser



def login_view(request):
    try:
        if request.method == "POST":
            email = request.POST['email'].lower()
            password = request.POST['password']
            user = CustomUser.objects.get(email=email, is_superuser=True, is_admin=True)
            if user.check_password(password):
                login(request, user)
                try:
                    next_page = request.GET.get('next')
                    return redirect(next_page)
                except:
                    return redirect('index')
            else:
                messages.warning(request, "Invailid password...")
        return render(request, 'user/login.html')
    except CustomUser.DoesNotExist:
        messages.warning(request, "User not found...")
        return render(request, 'user/login.html')
    except Exception as e:
        messages.warning(request, f"{e}")
        return render(request, 'user/login.html')
    

@login_required(login_url='/user/admin-login')
def logout_view(request):
    logout(request)
    return redirect(login_view)
