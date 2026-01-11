from django.contrib import admin
from .models import (
    User,
    FarmerProfile,
    VendorProfile,
    ExpertProfile,
    UserProfile,
    KYCRequest,
    FarmerProduct,
    VendorTool,
    FarmingTip,
    ExpertAppointment,
    ExpertChatThread,
    ExpertChatMessage,
)


@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ('email', 'role', 'is_verified', 'is_active', 'is_staff', 'date_joined')
    list_filter = ('role', 'is_verified', 'is_active', 'is_staff')
    search_fields = ('email',)
    ordering = ('-date_joined',)


@admin.register(KYCRequest)
class KYCRequestAdmin(admin.ModelAdmin):
    list_display = ('user', 'status', 'full_name', 'id_number', 'created_at', 'reviewed_at')
    list_filter = ('status',)
    search_fields = ('user__email', 'full_name', 'id_number')
    ordering = ('-created_at',)


admin.site.register(FarmerProfile)
admin.site.register(VendorProfile)
admin.site.register(ExpertProfile)
admin.site.register(UserProfile)
admin.site.register(FarmerProduct)
admin.site.register(VendorTool)
admin.site.register(FarmingTip)
admin.site.register(ExpertAppointment)
admin.site.register(ExpertChatThread)
admin.site.register(ExpertChatMessage)
