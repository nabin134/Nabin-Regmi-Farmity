from django.db import models
from django.conf import settings
from django.contrib.auth.models import (
    AbstractBaseUser, PermissionsMixin, BaseUserManager
)
from django.utils import timezone
from datetime import timedelta
import secrets

class UserManager(BaseUserManager):
    def create_user(self, email, password=None, role='buyer', phone=None, *, is_active=False, email_verified=False):
        if not email:
            raise ValueError("Email is required")

        email = self.normalize_email(email)
        user = self.model(
            email=email,
            role=role,
            phone=phone,
            is_active=is_active,
            email_verified=email_verified,
        )
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password):
        user = self.create_user(email, password, role='admin', is_active=True, email_verified=True)
        user.is_staff = True
        user.is_superuser = True
        user.save(using=self._db)
        return user


class User(AbstractBaseUser, PermissionsMixin):
    ROLE_CHOICES = (
        ('admin', 'Admin'),
        ('buyer', 'Buyer'),
        ('farmer', 'Farmer'),
        ('agricultural_expert', 'Agricultural Expert'),
        ('vendor', 'Vendor'),
    )

    email = models.EmailField(unique=True)
    # Required at signup, but kept nullable for existing rows/migrations.
    # Uniqueness is enforced across accounts (one phone -> one account).
    phone = models.CharField(max_length=10, unique=True, blank=True, null=True)
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='buyer')
    is_active = models.BooleanField(default=True)
    # Email ownership verification. Account activation is blocked until True.
    email_verified = models.BooleanField(default=False)
    is_verified = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    date_joined = models.DateTimeField(auto_now_add=True)

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    @property
    def username(self):
        """Return email as username for compatibility with django-allauth"""
        return self.email

    def __str__(self):
        return self.email

    def get_full_name(self):
        """Get the full name from the user's profile based on their role."""
        try:
            if self.role == 'farmer':
                if hasattr(self, 'farmer_profile'):
                    profile = self.farmer_profile
                    if profile and profile.name:
                        return profile.name
            elif self.role == 'vendor':
                if hasattr(self, 'vendor_profile'):
                    profile = self.vendor_profile
                    if profile and profile.company_name:
                        return profile.company_name
            elif self.role == 'agricultural_expert':
                if hasattr(self, 'expert_profile'):
                    profile = self.expert_profile
                    if profile and profile.name:
                        return profile.name
            elif self.role == 'buyer':
                if hasattr(self, 'user_profile'):
                    profile = self.user_profile
                    if profile and profile.name:
                        return profile.name
        except Exception:
            pass
        # Fallback to empty string if no name found
        return ''

    def get_short_name(self):
        """Get a short name (first name or email)."""
        full_name = self.get_full_name()
        if full_name:
            return full_name.split()[0] if ' ' in full_name else full_name
        return self.email.split('@')[0]


class FarmerProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='farmer_profile')
    name = models.CharField(max_length=255, blank=True, null=True)
    photo = models.ImageField(upload_to='farmer_photos/', blank=True, null=True)
    location = models.CharField(max_length=255, blank=True, null=True)
    contact = models.CharField(max_length=20, blank=True, null=True)
    farm_size = models.CharField(max_length=50, blank=True, null=True)
    crop_types = models.TextField(blank=True, null=True, help_text="Comma-separated list of crops")
    livestock_details = models.TextField(blank=True, null=True)

    def __str__(self):
        return self.name or self.user.email


class VendorProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='vendor_profile')
    company_name = models.CharField(max_length=255, blank=True, null=True)
    logo = models.ImageField(upload_to='vendor_logos/', blank=True, null=True)
    address = models.TextField(blank=True, null=True)
    contact = models.CharField(max_length=20, blank=True, null=True)
    website = models.URLField(max_length=255, blank=True, null=True)
    business_type = models.CharField(max_length=100, blank=True, null=True, help_text="e.g., Equipment supplier, Seeds & fertilizers")
    description = models.TextField(blank=True, null=True, help_text="Business description")

    def __str__(self):
        return self.company_name or self.user.email


class ExpertProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='expert_profile')
    name = models.CharField(max_length=255, blank=True, null=True)
    photo = models.ImageField(upload_to='expert_photos/', blank=True, null=True)
    qualification = models.CharField(max_length=255, blank=True, null=True)
    specialization = models.CharField(max_length=255, blank=True, null=True)
    experience = models.CharField(max_length=50, blank=True, null=True)

    def __str__(self):
        return self.name or self.user.email


class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='user_profile')
    name = models.CharField(max_length=255, blank=True, null=True)
    photo = models.ImageField(upload_to='user_photos/', blank=True, null=True)
    address = models.TextField(blank=True, null=True)
    phone = models.CharField(max_length=20, blank=True, null=True)

    def __str__(self):
        return self.name or self.user.email


class KYCRequest(models.Model):
    STATUS_PENDING = 'pending'
    STATUS_APPROVED = 'approved'
    STATUS_REJECTED = 'rejected'
    STATUS_CHOICES = (
        (STATUS_PENDING, 'Pending'),
        (STATUS_APPROVED, 'Approved'),
        (STATUS_REJECTED, 'Rejected'),
    )

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='kyc_requests')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_PENDING)
    full_name = models.CharField(max_length=255)
    id_number = models.CharField(max_length=100)
    id_document = models.FileField(upload_to='kyc_documents/')
    selfie = models.ImageField(upload_to='kyc_selfies/', blank=True, null=True)
    company_document = models.FileField(upload_to='kyc_company_documents/', blank=True, null=True, help_text="Required for vendors - Company registration or business license")
    certificate_document = models.FileField(upload_to='kyc_certificate_documents/', blank=True, null=True, help_text="Required for agricultural experts - Professional certificate or qualification")
    rejection_reason = models.TextField(blank=True, null=True)
    reviewed_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='kyc_reviews',
    )
    reviewed_at = models.DateTimeField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ('-created_at',)

    def __str__(self):
        return f"{self.user.email} - {self.status}"


class FarmerProduct(models.Model):
    farmer = models.ForeignKey(FarmerProfile, on_delete=models.CASCADE, related_name='products')
    name = models.CharField(max_length=255)
    quantity = models.DecimalField(max_digits=12, decimal_places=2)
    unit = models.CharField(max_length=50, default='kg')
    price_per_unit = models.DecimalField(max_digits=12, decimal_places=2)
    image = models.ImageField(upload_to='product_images/', blank=True, null=True)
    is_available = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ('-created_at',)

    def __str__(self):
        return f"{self.name} ({self.farmer.user.email})"


class VendorTool(models.Model):
    vendor = models.ForeignKey(VendorProfile, on_delete=models.CASCADE, related_name='tools')
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    stock_quantity = models.PositiveIntegerField(default=0)
    price = models.DecimalField(max_digits=12, decimal_places=2)
    image = models.ImageField(upload_to='tool_images/', blank=True, null=True)
    is_available = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ('-created_at',)

    def __str__(self):
        return f"{self.name} ({self.vendor.user.email})"


class FarmingTip(models.Model):
    APPROVAL_PENDING = 'pending'
    APPROVAL_APPROVED = 'approved'
    APPROVAL_REJECTED = 'rejected'
    APPROVAL_CHOICES = (
        (APPROVAL_PENDING, 'Pending approval'),
        (APPROVAL_APPROVED, 'Approved'),
        (APPROVAL_REJECTED, 'Rejected'),
    )
    expert = models.ForeignKey(ExpertProfile, on_delete=models.CASCADE, related_name='tips')
    title = models.CharField(max_length=255)
    content = models.TextField()
    image = models.ImageField(upload_to='expert_content_images/', blank=True, null=True)
    is_published = models.BooleanField(default=False, help_text='Set to True when admin approves.')
    approval_status = models.CharField(
        max_length=20,
        choices=APPROVAL_CHOICES,
        default=APPROVAL_PENDING,
        help_text='Content is visible to users only when Approved by admin.'
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ('-created_at',)

    def __str__(self):
        return self.title


class ExpertAppointment(models.Model):
    STATUS_PENDING = 'pending'
    STATUS_ACCEPTED = 'accepted'
    STATUS_REJECTED = 'rejected'
    STATUS_CHOICES = (
        (STATUS_PENDING, 'Pending'),
        (STATUS_ACCEPTED, 'Accepted'),
        (STATUS_REJECTED, 'Rejected'),
    )

    VISIT_VISITED = 'visited'
    VISIT_WILL_VISIT = 'will_visit'
    VISIT_WAITING = 'waiting'
    VISIT_CHOICES = (
        (VISIT_VISITED, 'Visited'),
        (VISIT_WILL_VISIT, 'Will visit'),
        (VISIT_WAITING, 'They have to wait'),
    )

    expert = models.ForeignKey(ExpertProfile, on_delete=models.CASCADE, related_name='appointments')
    requester = models.ForeignKey(User, on_delete=models.CASCADE, related_name='appointments')
    requested_date = models.DateField()
    requested_time = models.TimeField()
    message = models.TextField(blank=True, null=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_PENDING)
    response_message = models.TextField(blank=True, null=True, help_text='Doctor message: reason for reject or note for accept.')
    visit_status = models.CharField(max_length=20, choices=VISIT_CHOICES, blank=True, null=True, help_text='For accepted appointments: Visited / Will visit / They have to wait.')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ('-created_at',)

    def __str__(self):
        return f"{self.requester.email} -> {self.expert.user.email} ({self.status})"


class ExpertAvailability(models.Model):
    """Dates (and optional time slots) when the expert is available for appointments."""
    expert = models.ForeignKey(ExpertProfile, on_delete=models.CASCADE, related_name='availability')
    date = models.DateField()
    start_time = models.TimeField(blank=True, null=True, help_text='Optional: slot start. Empty means whole day.')
    end_time = models.TimeField(blank=True, null=True, help_text='Optional: slot end. Empty means whole day.')
    notes = models.CharField(max_length=255, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ('date', 'start_time')
        verbose_name_plural = 'Expert availabilities'

    def __str__(self):
        if self.start_time and self.end_time:
            return f"{self.expert.user.email} - {self.date} {self.start_time}-{self.end_time}"
        return f"{self.expert.user.email} - {self.date}"


class ExpertChatThread(models.Model):
    expert = models.ForeignKey(ExpertProfile, on_delete=models.CASCADE, related_name='chat_threads')
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='chat_threads')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ('-updated_at',)

    def __str__(self):
        return f"Thread {self.id}"


class ExpertChatMessage(models.Model):
    thread = models.ForeignKey(ExpertChatThread, on_delete=models.CASCADE, related_name='messages')
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name='chat_messages')
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ('created_at',)

    def __str__(self):
        return f"Msg {self.id}"


class Order(models.Model):
    STATUS_PENDING = 'pending'
    STATUS_CONFIRMED = 'confirmed'
    STATUS_SHIPPED = 'shipped'
    STATUS_DELIVERED = 'delivered'
    STATUS_CANCELLED = 'cancelled'
    STATUS_CHOICES = (
        (STATUS_PENDING, 'Pending'),
        (STATUS_CONFIRMED, 'Confirmed'),
        (STATUS_SHIPPED, 'Shipped'),
        (STATUS_DELIVERED, 'Delivered'),
        (STATUS_CANCELLED, 'Cancelled'),
    )

    PAYMENT_COD = 'cod'
    PAYMENT_ESEWA = 'esewa'
    PAYMENT_CHOICES = (
        (PAYMENT_COD, 'Cash on Delivery'),
        (PAYMENT_ESEWA, 'eSewa'),
    )

    PAYMENT_STATUS_PENDING = 'pending'
    PAYMENT_STATUS_COMPLETED = 'completed'
    PAYMENT_STATUS_FAILED = 'failed'
    PAYMENT_STATUS_CHOICES = (
        (PAYMENT_STATUS_PENDING, 'Pending'),
        (PAYMENT_STATUS_COMPLETED, 'Completed'),
        (PAYMENT_STATUS_FAILED, 'Failed'),
    )

    buyer = models.ForeignKey(User, on_delete=models.CASCADE, related_name='orders')
    tool = models.ForeignKey(VendorTool, on_delete=models.CASCADE, related_name='orders', null=True, blank=True)
    crop = models.ForeignKey(FarmerProduct, on_delete=models.CASCADE, related_name='orders', null=True, blank=True)
    quantity = models.PositiveIntegerField(default=1)
    total_amount = models.DecimalField(max_digits=12, decimal_places=2)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_PENDING)
    payment_method = models.CharField(max_length=20, choices=PAYMENT_CHOICES, default=PAYMENT_COD, blank=True, null=True)
    payment_status = models.CharField(max_length=20, choices=PAYMENT_STATUS_CHOICES, default=PAYMENT_STATUS_PENDING, blank=True, null=True)
    shipping_address = models.TextField(blank=True, null=True, help_text='Delivery location/address')
    contact_number = models.CharField(max_length=20, blank=True, null=True, help_text='Phone number (required for delivery)')
    order_email = models.EmailField(blank=True, null=True, help_text='Email for this order (optional)')
    tracking_number = models.CharField(max_length=100, blank=True, null=True)
    notes = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    # Payout to farmer/vendor: all amounts collected by admin; paid out (e.g. weekly) with notification
    PAYOUT_PENDING = 'pending_payout'
    PAYOUT_PAID = 'paid'
    PAYOUT_STATUS_CHOICES = (
        (PAYOUT_PENDING, 'Pending payout'),
        (PAYOUT_PAID, 'Paid to seller'),
    )
    payout_status = models.CharField(
        max_length=20, choices=PAYOUT_STATUS_CHOICES, default=PAYOUT_PENDING, blank=True, null=True
    )
    payout_at = models.DateTimeField(blank=True, null=True, help_text='When admin paid this order’s amount to farmer/vendor')

    class Meta:
        ordering = ('-created_at',)

    def __str__(self):
        item = self.tool.name if self.tool else (self.crop.name if self.crop else 'Unknown')
        return f"Order #{self.id} - {item} - {self.buyer.email}"

    def get_seller_user(self):
        """Return the User (farmer or vendor) who should receive payout for this order."""
        if self.crop and self.crop.farmer:
            return getattr(self.crop.farmer, 'user', None)
        if self.tool and self.tool.vendor:
            return getattr(self.tool.vendor, 'user', None)
        return None

    def get_seller_display_name(self):
        """Display name for farmer or vendor."""
        if self.crop and self.crop.farmer:
            return self.crop.farmer.name or self.crop.farmer.user.email
        if self.tool and self.tool.vendor:
            return self.tool.vendor.company_name or self.tool.vendor.user.email
        return 'Unknown'


class CropSale(models.Model):
    """Track sales of crops by farmers"""
    crop = models.ForeignKey(FarmerProduct, on_delete=models.CASCADE, related_name='sales')
    order = models.ForeignKey(Order, on_delete=models.CASCADE, related_name='crop_sales', null=True, blank=True)
    quantity_sold = models.DecimalField(max_digits=12, decimal_places=2)
    price_per_unit = models.DecimalField(max_digits=12, decimal_places=2)
    total_amount = models.DecimalField(max_digits=12, decimal_places=2)
    sold_to = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='purchased_crops')
    sold_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ('-sold_at',)

    def __str__(self):
        return f"Sale of {self.quantity_sold} {self.crop.unit} {self.crop.name} - Rs. {self.total_amount}"


class OTP(models.Model):
    """Store OTPs for login + other one-time verification flows."""
    PURPOSE_LOGIN = 'login'
    PURPOSE_EMAIL_VERIFY = 'email_verify'
    PURPOSE_CHOICES = (
        (PURPOSE_LOGIN, 'Login'),
        (PURPOSE_EMAIL_VERIFY, 'Email verification'),
    )

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='otps')
    purpose = models.CharField(max_length=20, choices=PURPOSE_CHOICES, default=PURPOSE_LOGIN)
    otp_code = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_used = models.BooleanField(default=False)
    is_verified = models.BooleanField(default=False)
    
    class Meta:
        ordering = ('-created_at',)
        indexes = [
            models.Index(fields=['user', 'purpose', 'is_used', 'is_verified']),
        ]
    
    def __str__(self):
        return f"OTP for {self.user.email} - {self.otp_code}"
    
    def is_expired(self):
        """Check if OTP has expired"""
        return timezone.now() > self.expires_at
    
    def is_valid(self):
        """Check if OTP is valid (not used, not expired, not verified)"""
        return not self.is_used and not self.is_expired() and not self.is_verified
    
    @classmethod
    def generate_otp(cls, user, expiry_minutes=10, purpose=PURPOSE_LOGIN):
        """Generate a new OTP for user (scoped by purpose)."""
        # Delete old unused OTPs for this user/purpose
        cls.objects.filter(user=user, purpose=purpose, is_used=False, is_verified=False).delete()
        
        # Generate 6-digit OTP
        otp_code = ''.join([str(secrets.randbelow(10)) for _ in range(6)])
        
        # Create OTP
        otp = cls.objects.create(
            user=user,
            purpose=purpose,
            otp_code=otp_code,
            expires_at=timezone.now() + timedelta(minutes=expiry_minutes)
        )
        
        return otp


# ======================
# Customer Support
# ======================

class FAQ(models.Model):
    """Default/frequently asked questions shown in the support hub."""
    question = models.CharField(max_length=500)
    answer = models.TextField()
    category = models.CharField(max_length=100, blank=True, null=True, help_text="e.g. Account, Orders, Payments")
    order = models.PositiveIntegerField(default=0, help_text="Display order (lower first)")
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ('order', 'created_at')
        verbose_name = 'FAQ'
        verbose_name_plural = 'FAQs'

    def __str__(self):
        return self.question[:60] + ('...' if len(self.question) > 60 else '')


class SupportStaffProfile(models.Model):
    """Users who can handle support tickets (assigned by admin)."""
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='support_staff_profile')
    is_available = models.BooleanField(default=True, help_text="Show as available for direct contact")
    contact_info = models.CharField(max_length=255, blank=True, null=True, help_text="e.g. phone or extra email")
    display_name = models.CharField(max_length=100, blank=True, null=True, help_text="Optional display name for support")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = 'Support staff profile'
        verbose_name_plural = 'Support staff profiles'

    def __str__(self):
        name = self.display_name or self.user.get_full_name() or self.user.email
        return f"{name} (Support)"


class SupportTicket(models.Model):
    STATUS_OPEN = 'open'
    STATUS_IN_PROGRESS = 'in_progress'
    STATUS_ANSWERED = 'answered'
    STATUS_CLOSED = 'closed'
    STATUS_CHOICES = (
        (STATUS_OPEN, 'Open'),
        (STATUS_IN_PROGRESS, 'In Progress'),
        (STATUS_ANSWERED, 'Answered'),
        (STATUS_CLOSED, 'Closed'),
    )

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='support_tickets')
    subject = models.CharField(max_length=255)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_OPEN)
    assigned_to = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='assigned_support_tickets',
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ('-updated_at',)

    def __str__(self):
        return f"#{self.id} - {self.subject} ({self.user.email})"


class SupportMessage(models.Model):
    """Messages in a support ticket thread."""
    ticket = models.ForeignKey(SupportTicket, on_delete=models.CASCADE, related_name='messages')
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name='support_messages')
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ('created_at',)

    def __str__(self):
        return f"Msg {self.id} (Ticket #{self.ticket_id})"


class UserNotification(models.Model):
    """In-app notifications for users (orders, KYC, appointments, support, etc.)."""
    TYPE_ORDER = 'order'
    TYPE_KYC = 'kyc'
    TYPE_APPOINTMENT = 'appointment'
    TYPE_SUPPORT = 'support'
    TYPE_CHAT = 'chat'
    TYPE_INFO = 'info'
    TYPE_CHOICES = (
        (TYPE_ORDER, 'Order'),
        (TYPE_KYC, 'KYC'),
        (TYPE_APPOINTMENT, 'Appointment'),
        (TYPE_SUPPORT, 'Support'),
        (TYPE_CHAT, 'Chat'),
        (TYPE_INFO, 'Info'),
    )

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='notifications'
    )
    title = models.CharField(max_length=255)
    message = models.TextField(blank=True)
    link = models.CharField(max_length=500, blank=True, help_text='URL or hash to open when clicked')
    notification_type = models.CharField(max_length=20, choices=TYPE_CHOICES, default=TYPE_INFO)
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ('-created_at',)

    def __str__(self):
        return f"{self.title} ({self.user.email})"
