from rest_framework import serializers
from user.models import CustomUser



class UserSerializer(serializers.ModelSerializer):
    
    class Meta:
        model = CustomUser
        fields = ['id', 'email', 'first_name', 'last_name', 'phone', 'password', 'updated_at']
        
    def to_representation(self, instance):
        rep = super().to_representation(instance)
        rep.pop('password')
        rep['is_active'] = instance.is_active
        return rep
    


class UserLoginSerializer(serializers.Serializer):
    """
    User Login Serializer
    """
    email = serializers.EmailField()
    password = serializers.CharField()
    
    class Meta:
        fields = ['email', 'password']
        


class UserUpdateSerializer(serializers.ModelSerializer):
    
    class Meta:
        model = CustomUser
        fields = ['id', 'email', 'first_name', 'last_name', 'phone']
        
    def to_representation(self, instance):
        rep = super().to_representation(instance)
        rep['is_active'] = instance.is_active
        rep['email'] = instance.email
        return rep
    

