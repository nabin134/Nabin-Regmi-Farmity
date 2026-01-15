from django.contrib import admin
from django.utils import timezone
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
    Order,
    CropSale,
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
    actions = ['approve_kyc', 'reject_kyc']
    
    def approve_kyc(self, request, queryset):
        """Approve selected KYC requests and verify users"""
        from django.utils import timezone
        updated = 0
        for kyc in queryset.filter(status='pending'):
            kyc.status = 'approved'
            kyc.reviewed_by = request.user
            kyc.reviewed_at = timezone.now()
            kyc.save()
            # Verify the user
            kyc.user.is_verified = True
            kyc.user.save()
            updated += 1
        self.message_user(request, f'{updated} KYC request(s) approved and users verified.')
    approve_kyc.short_description = "Approve selected KYC requests"
    
    def reject_kyc(self, request, queryset):
        """Reject selected KYC requests"""
        from django.utils import timezone
        updated = 0
        for kyc in queryset.filter(status='pending'):
            kyc.status = 'rejected'
            kyc.reviewed_by = request.user
            kyc.reviewed_at = timezone.now()
            kyc.save()
            # Unverify the user
            kyc.user.is_verified = False
            kyc.user.save()
            updated += 1
        self.message_user(request, f'{updated} KYC request(s) rejected.')
    reject_kyc.short_description = "Reject selected KYC requests"
    
    def save_model(self, request, obj, form, change):
        """Override save to auto-verify user when KYC is approved"""
        if change and 'status' in form.changed_data:
            if obj.status == 'approved':
                obj.user.is_verified = True
                obj.user.save()
            elif obj.status == 'rejected':
                obj.user.is_verified = False
                obj.user.save()
        super().save_model(request, obj, form, change)


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
admin.site.register(Order)
admin.site.register(CropSale)
