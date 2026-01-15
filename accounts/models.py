from django.db import models
from django.contrib.auth.models import (
    AbstractBaseUser, PermissionsMixin, BaseUserManager
)

class UserManager(BaseUserManager):
    def create_user(self, email, password=None, role='buyer'):
        if not email:
            raise ValueError("Email is required")

        email = self.normalize_email(email)
        user = self.model(email=email, role=role)
        user.set_password(password)
        user.is_active = True
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password):
        user = self.create_user(email, password, role='admin')
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
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='buyer')
    is_active = models.BooleanField(default=True)
    is_verified = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    date_joined = models.DateTimeField(auto_now_add=True)

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

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
    expert = models.ForeignKey(ExpertProfile, on_delete=models.CASCADE, related_name='tips')
    title = models.CharField(max_length=255)
    content = models.TextField()
    is_published = models.BooleanField(default=True)
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

    expert = models.ForeignKey(ExpertProfile, on_delete=models.CASCADE, related_name='appointments')
    requester = models.ForeignKey(User, on_delete=models.CASCADE, related_name='appointments')
    requested_date = models.DateField()
    requested_time = models.TimeField()
    message = models.TextField(blank=True, null=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_PENDING)
    response_message = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ('-created_at',)

    def __str__(self):
        return f"{self.requester.email} -> {self.expert.user.email} ({self.status})"


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
    shipping_address = models.TextField(blank=True, null=True)
    tracking_number = models.CharField(max_length=100, blank=True, null=True)
    notes = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ('-created_at',)

    def __str__(self):
        item = self.tool.name if self.tool else (self.crop.name if self.crop else 'Unknown')
        return f"Order #{self.id} - {item} - {self.buyer.email}"


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
