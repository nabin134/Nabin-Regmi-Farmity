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
    ExpertAvailability,
    ExpertChatThread,
    ExpertChatMessage,
    Order,
    CropSale,
    FAQ,
    LandingFeature,
    SupportStaffProfile,
    SupportTicket,
    SupportMessage,
    UserNotification,
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
admin.site.register(ExpertAvailability)
admin.site.register(ExpertChatThread)
admin.site.register(ExpertChatMessage)
admin.site.register(Order)
admin.site.register(CropSale)


# Customer Support
@admin.register(FAQ)
class FAQAdmin(admin.ModelAdmin):
    list_display = ('question', 'category', 'order', 'is_active', 'created_at')
    list_filter = ('category', 'is_active')
    search_fields = ('question', 'answer')
    ordering = ('order',)


@admin.register(LandingFeature)
class LandingFeatureAdmin(admin.ModelAdmin):
    list_display = ('title', 'label', 'link_target', 'display_order', 'is_active', 'created_at')
    list_editable = ('display_order', 'is_active')
    list_filter = ('is_active',)
    search_fields = ('title', 'label', 'short_description')
    ordering = ('display_order',)
    fieldsets = (
        (None, {'fields': ('title', 'label', 'short_description', 'link_target', 'cta_text')}),
        ('Image', {'fields': ('image', 'image_url'), 'description': 'Upload an image or set image_url (URL used if no file).'}),
        ('Display', {'fields': ('display_order', 'is_active')}),
    )


@admin.register(SupportStaffProfile)
class SupportStaffProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'display_name', 'is_available', 'contact_info')
    list_filter = ('is_available',)
    search_fields = ('user__email', 'display_name')


@admin.register(SupportTicket)
class SupportTicketAdmin(admin.ModelAdmin):
    list_display = ('id', 'subject', 'user', 'status', 'assigned_to', 'created_at')
    list_filter = ('status',)
    search_fields = ('subject', 'user__email')
    raw_id_fields = ('user', 'assigned_to')


@admin.register(SupportMessage)
class SupportMessageAdmin(admin.ModelAdmin):
    list_display = ('id', 'ticket', 'sender', 'created_at')
    raw_id_fields = ('ticket', 'sender')


@admin.register(UserNotification)
class UserNotificationAdmin(admin.ModelAdmin):
    list_display = ('id', 'user', 'title', 'notification_type', 'is_read', 'created_at')
    list_filter = ('notification_type', 'is_read')
    search_fields = ('title', 'message', 'user__email')
    raw_id_fields = ('user',)
    readonly_fields = ('created_at',)
