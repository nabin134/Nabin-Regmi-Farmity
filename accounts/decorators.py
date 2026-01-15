"""
Custom decorators for role-based and KYC-based access control
"""
from functools import wraps
from django.shortcuts import redirect
from django.contrib import messages
from .models import KYCRequest


def kyc_required(view_func):
    """
    Decorator to ensure user has approved KYC before accessing features.
    Only applies to roles that require KYC: farmer, vendor, agricultural_expert
    """
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        user = request.user
        
        # Check if user role requires KYC
        if user.role in {'farmer', 'vendor', 'agricultural_expert'}:
            kyc_request = user.kyc_requests.first()
            kyc_status = kyc_request.status if kyc_request else None
            
            # If KYC is not approved, restrict access
            if kyc_status != KYCRequest.STATUS_APPROVED:
                messages.warning(
                    request,
                    'KYC verification is required to access this feature. Please complete your KYC verification first.'
                )
                return redirect('kyc')
        
        # If buyer or admin, allow access (no KYC required)
        return view_func(request, *args, **kwargs)
    
    return _wrapped_view


def kyc_optional(view_func):
    """
    Decorator that allows access but passes KYC status to the view.
    Used for views that show restricted content but don't block access.
    """
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        user = request.user
        kyc_approved = False
        
        if user.role in {'farmer', 'vendor', 'agricultural_expert'}:
            kyc_request = user.kyc_requests.first()
            kyc_status = kyc_request.status if kyc_request else None
            kyc_approved = (kyc_status == KYCRequest.STATUS_APPROVED)
        elif user.role in {'buyer', 'admin'}:
            # Buyers and admins don't need KYC
            kyc_approved = True
        
        # Add KYC status to request for template use
        request.kyc_approved = kyc_approved
        return view_func(request, *args, **kwargs)
    
    return _wrapped_view
