/**
 * Farmity: AJAX form posts, optional confirm (Yes/Cancel), toast feedback, DOM updates.
 * Depends on form-validation.js (showConfirmation, showToast / showSuccess / showError).
 */
(function () {
    'use strict';

    function getCookie(name) {
        const m = document.cookie.match(new RegExp('(^|; )' + name.replace(/([.$?*|{}()[\]\\/+^])/g, '\\$1') + '=([^;]*)'));
        return m ? decodeURIComponent(m[2]) : '';
    }

    function getCsrfToken() {
        const el = document.querySelector('[name=csrfmiddlewaretoken]');
        if (el && el.value) return el.value;
        return getCookie('csrftoken');
    }

    function farmityConfirm(message, type = 'warning') {
        const dlg = typeof showConfirmation === 'function' ? showConfirmation : null;
        const prompt = (message || '').trim() || 'Are you sure you want to proceed?';
        if (dlg) {
            return dlg({
                title: type === 'danger' ? 'Delete Confirmation' : 'Confirm',
                message: prompt,
                confirmText: type === 'danger' ? 'Delete' : 'Yes',
                cancelText: 'Cancel',
                type: type,
            });
        }
        return Promise.resolve(window.confirm(prompt));
    }

    function applyFieldErrors(form, fieldErrors) {
        if (!form || !fieldErrors || typeof fieldErrors !== 'object') return;
        Object.keys(fieldErrors).forEach(function (name) {
            const msg = fieldErrors[name];
            const field = form.querySelector('[name="' + name + '"]');
            let holder = document.getElementById(form.id ? form.id + 'FieldError-' + name : '');
            if (!holder && field) {
                holder = field.closest('.form-group')?.querySelector('.farmity-field-error');
            }
            if (!holder && field) {
                holder = document.createElement('p');
                holder.className = 'farmity-field-error';
                holder.setAttribute('role', 'alert');
                field.closest('.form-group')?.appendChild(holder) || field.parentElement.appendChild(holder);
            }
            if (holder) {
                holder.textContent = msg;
                holder.style.display = 'block';
                holder.style.color = '#dc3545';
                holder.style.fontSize = '0.8125rem';
                holder.style.marginTop = '0.35rem';
            }
            if (field) field.classList.add('field-invalid');
        });
    }

    function clearFarmityFieldErrors(form) {
        if (!form) return;
        form.querySelectorAll('.farmity-field-error').forEach(function (el) {
            el.textContent = '';
            el.style.display = 'none';
        });
        form.querySelectorAll('.field-invalid').forEach(function (el) {
            el.classList.remove('field-invalid');
        });
    }

    function normalizeResponse(data) {
        if (!data || typeof data !== 'object') return { ok: false, message: 'Something went wrong.' };
        if (Object.prototype.hasOwnProperty.call(data, 'ok')) return data;
        if (Object.prototype.hasOwnProperty.call(data, 'success')) {
            const payload = data.data && typeof data.data === 'object' ? data.data : {};
            return Object.assign({}, payload, {
                ok: !!data.success,
                message: data.message || '',
                field_errors: payload.field_errors || data.field_errors || null,
            });
        }
        return data;
    }

    function applyNativeValidationHints(form) {
        if (!form) return true;
        const dateField = form.querySelector('[name="requested_date"]');
        if (dateField) {
            const value = (dateField.value || '').trim();
            dateField.setCustomValidity(value ? '' : 'Please select an appointment date.');
        }
        const timeField = form.querySelector('[name="requested_time"]');
        if (timeField) {
            const value = (timeField.value || '').trim();
            timeField.setCustomValidity(value ? '' : 'Please select an appointment time.');
        }
        if (typeof form.checkValidity === 'function' && !form.checkValidity()) {
            if (typeof form.reportValidity === 'function') form.reportValidity();
            return false;
        }
        return true;
    }

    async function submitFarmityForm(form) {
        const url = form.getAttribute('action') || window.location.pathname + window.location.search;
        const useConfirm = form.getAttribute('data-farmity-confirm') === '1';
        if (useConfirm) {
            let confirmType = 'warning';
            const confirmMessage = (form.getAttribute('data-farmity-confirm-message') || '').trim() || 'Are you sure you want to proceed?';
            const forcedType = (form.getAttribute('data-farmity-confirm-type') || '').trim();
            
            // Determine confirmation type based on action
            if (form.querySelector('[name*="delete"]') || form.querySelector('[name*="remove"]') || 
                confirmMessage.toLowerCase().includes('delete') || confirmMessage.toLowerCase().includes('remove')) {
                confirmType = 'danger';
            }
            if (forcedType) confirmType = forcedType;
            
            const ok = await farmityConfirm(confirmMessage, confirmType);
            if (!ok) return;
        }

        clearFarmityFieldErrors(form);
        if (!applyNativeValidationHints(form)) return;
        const fd = new FormData(form);
        fd.set('ajax', '1');

        const submitBtn = form.querySelector('button[type="submit"], input[type="submit"]');
        const prevText = submitBtn ? submitBtn.innerHTML : '';
        if (submitBtn) {
            submitBtn.disabled = true;
            submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i>';
        }

        try {
            const res = await fetch(url, {
                method: 'POST',
                body: fd,
                credentials: 'same-origin',
                headers: {
                    'X-Requested-With': 'XMLHttpRequest',
                    Accept: 'application/json',
                    'X-CSRFToken': getCsrfToken(),
                },
            });
            let data = {};
            const ct = res.headers.get('content-type') || '';
            if (ct.indexOf('application/json') !== -1) {
                data = normalizeResponse(await res.json());
            } else {
                const text = await res.text();
                if (typeof showError === 'function') {
                    showError('Unexpected response from server.');
                }
                if (submitBtn) {
                    submitBtn.disabled = false;
                    submitBtn.innerHTML = prevText;
                }
                return;
            }

            if (data.field_errors) {
                applyFieldErrors(form, data.field_errors);
            }

            if (data.ok) {
                if (typeof showSuccess === 'function') {
                    showSuccess(data.message || 'Saved successfully.');
                }
                const removeSel = form.getAttribute('data-farmity-remove-selector');
                if (removeSel) {
                    const el = document.querySelector(removeSel);
                    if (el) el.remove();
                }
                if (data.removed_tip_id != null) {
                    const row = document.querySelector('[data-tip-row="' + data.removed_tip_id + '"]');
                    if (row) row.remove();
                }
                if (data.removed_availability_id != null) {
                    const row = document.querySelector('[data-availability-row="' + data.removed_availability_id + '"]');
                    if (row) row.remove();
                }
                if (data.appointment_status && data.appointment_status.id != null) {
                    const card = document.querySelector('[data-appointment-row="' + data.appointment_status.id + '"]');
                    if (card) {
                        const statusBadge = card.querySelector('.appointment-status-badge');
                        const statusText = card.querySelector('.appointment-status-text');
                        const responseMessage = card.querySelector('.appointment-response-message');
                        
                        if (statusBadge) {
                            statusBadge.className = 'appointment-status-badge ' + data.appointment_status.status;
                            const statusTextMap = {
                                'pending': 'Pending',
                                'accepted': 'Accepted',
                                'rejected': 'Rejected',
                                'cancelled': 'Cancelled'
                            };
                            statusBadge.textContent = statusTextMap[data.appointment_status.status] || data.appointment_status.status;
                        }
                        
                        if (statusText) {
                            statusText.textContent = data.appointment_status.status;
                        }
                        
                        if (responseMessage && data.appointment_status.response_message) {
                            responseMessage.textContent = data.appointment_status.response_message;
                            responseMessage.style.display = 'block';
                        }
                        
                        // Hide action buttons if appointment is no longer pending
                        const actionButtons = card.querySelector('.appointment-actions');
                        if (actionButtons && data.appointment_status.status !== 'pending') {
                            actionButtons.style.display = 'none';
                        }
                    }
                }
                if (data.new_availability) {
                    const availabilityGrid = document.querySelector('.availability-grid');
                    if (availabilityGrid && data.new_availability.id) {
                        const newCard = document.createElement('div');
                        newCard.className = 'availability-date-card';
                        newCard.setAttribute('data-availability-row', data.new_availability.id);
                        
                        const date = new Date(data.new_availability.date);
                        const dateStr = date.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
                        const timeStr = data.new_availability.start_time && data.new_availability.end_time ? 
                            `${data.new_availability.start_time} – ${data.new_availability.end_time}` : '';
                        const notes = data.new_availability.notes || '';
                        
                        newCard.innerHTML = `
                            <div class="date-main">
                                <strong>${dateStr}</strong>
                                ${timeStr ? `<div class="date-time">${timeStr}</div>` : ''}
                                ${notes ? `<div class="date-notes">${notes}</div>` : ''}
                            </div>
                            <form method="POST" style="margin: 0;" data-farmity-ajax="1" data-farmity-confirm="1" data-farmity-confirm-type="danger" data-farmity-confirm-message="Are you sure you want to remove this availability date?" data-farmity-remove-selector="[data-availability-row='${data.new_availability.id}']">
                                <input type="hidden" name="return_section" value="availability">
                                <input type="hidden" name="remove_availability" value="1">
                                <input type="hidden" name="availability_id" value="${data.new_availability.id}">
                                <button type="submit" class="btn btn-danger btn-icon-sm" title="Remove"><i class="fas fa-trash-alt"></i></button>
                            </form>
                        `;
                        
                        availabilityGrid.appendChild(newCard);
                        
                        // Update the count in the title
                        const titleElement = document.querySelector('.availability-list-title');
                        if (titleElement) {
                            const currentCount = availabilityGrid.children.length;
                            titleElement.innerHTML = `<i class="fas fa-list"></i> Your available dates (${currentCount})`;
                        }
                    }
                }
                if (data.new_availabilities && Array.isArray(data.new_availabilities)) {
                    const availabilityGrid = document.querySelector('.availability-grid');
                    if (availabilityGrid) {
                        data.new_availabilities.forEach(function(avail) {
                            const newCard = document.createElement('div');
                            newCard.className = 'availability-date-card';
                            newCard.setAttribute('data-availability-row', avail.id);
                            
                            const date = new Date(avail.date);
                            const dateStr = date.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
                            const timeStr = avail.start_time && avail.end_time ? 
                                `${avail.start_time} – ${avail.end_time}` : '';
                            const notes = avail.notes || '';
                            
                            newCard.innerHTML = `
                                <div class="date-main">
                                    <strong>${dateStr}</strong>
                                    ${timeStr ? `<div class="date-time">${timeStr}</div>` : ''}
                                    ${notes ? `<div class="date-notes">${notes}</div>` : ''}
                                </div>
                                <form method="POST" style="margin: 0;" data-farmity-ajax="1" data-farmity-confirm="1" data-farmity-confirm-type="danger" data-farmity-confirm-message="Are you sure you want to remove this availability date?" data-farmity-remove-selector="[data-availability-row='${avail.id}']">
                                    <input type="hidden" name="return_section" value="availability">
                                    <input type="hidden" name="remove_availability" value="1">
                                    <input type="hidden" name="availability_id" value="${avail.id}">
                                    <button type="submit" class="btn btn-danger btn-icon-sm" title="Remove"><i class="fas fa-trash-alt"></i></button>
                                </form>
                            `;
                            
                            availabilityGrid.appendChild(newCard);
                        });
                        
                        // Update the count in the title
                        const titleElement = document.querySelector('.availability-list-title');
                        if (titleElement) {
                            const currentCount = availabilityGrid.children.length;
                            titleElement.innerHTML = `<i class="fas fa-list"></i> Your available dates (${currentCount})`;
                        }
                    }
                }
                if (data.photo_url) {
                    const img = document.querySelector(form.getAttribute('data-farmity-photo-target') || '.profile-img-large');
                    if (img && img.tagName === 'IMG') img.src = data.photo_url;
                }
                if (data.email) {
                    document.querySelectorAll('.profile-value-text-email, [data-profile-email-display]').forEach(function (el) {
                        el.textContent = data.email;
                    });
                    form.querySelectorAll('input[name="email"]').forEach(function (inp) {
                        inp.value = data.email;
                    });
                }
                // Handle profile form toggle back to view mode
                if (form.id === 'farmerProfileForm') {
                    const viewMode = document.getElementById('farmerProfileViewMode');
                    const formWrap = document.getElementById('farmerProfileFormWrap');
                    const editBtnText = document.getElementById('farmerEditBtnText');
                    if (viewMode && formWrap) {
                        // Update profile display fields with form values
                        const nameField = form.querySelector('[name="name"]');
                        const emailField = form.querySelector('[name="email"]');
                        const contactField = form.querySelector('[name="contact"]');
                        const locationField = form.querySelector('[name="location"]');
                        const farmSizeField = form.querySelector('[name="farm_size"]');
                        const cropTypesField = form.querySelector('[name="crop_types"]');
                        const livestockField = form.querySelector('[name="livestock_details"]');
                        
                        if (nameField) {
                            const nameDisplay = document.querySelector('[data-profile-name-display]');
                            if (nameDisplay) nameDisplay.textContent = nameField.value || 'Not set';
                        }
                        if (emailField) {
                            const emailDisplay = document.querySelector('[data-profile-email-display]');
                            if (emailDisplay) emailDisplay.textContent = emailField.value || 'Not set';
                        }
                        if (contactField) {
                            const contactDisplay = Array.from(document.querySelectorAll('.profile-info-value')).find(el => el.textContent.includes('Not set') || el.textContent.includes('{{ profile.contact }}'));
                            if (contactDisplay) {
                                const icon = contactDisplay.querySelector('i');
                                contactDisplay.innerHTML = `<i class="fas fa-phone"></i> ${contactField.value || 'Not set'}`;
                            }
                        }
                        if (locationField) {
                            const locationDisplay = Array.from(document.querySelectorAll('.profile-info-value')).find(el => el.textContent.includes('Not set') || el.textContent.includes('{{ profile.location }}'));
                            if (locationDisplay) {
                                const icon = locationDisplay.querySelector('i');
                                locationDisplay.innerHTML = `<i class="fas fa-map-marker-alt"></i> ${locationField.value || 'Not set'}`;
                            }
                        }
                        if (farmSizeField) {
                            const farmSizeDisplay = Array.from(document.querySelectorAll('.profile-info-value')).find(el => el.textContent.includes('Not set') || el.textContent.includes('{{ profile.farm_size }}'));
                            if (farmSizeDisplay) {
                                const icon = farmSizeDisplay.querySelector('i');
                                farmSizeDisplay.innerHTML = `<i class="fas fa-tractor"></i> ${farmSizeField.value || 'Not set'}`;
                            }
                        }
                        if (cropTypesField) {
                            const cropTypesDisplay = Array.from(document.querySelectorAll('.profile-info-value')).find(el => el.textContent.includes('Not set') || el.textContent.includes('{{ profile.crop_types }}'));
                            if (cropTypesDisplay) {
                                const icon = cropTypesDisplay.querySelector('i');
                                cropTypesDisplay.innerHTML = `<i class="fas fa-seedling"></i> ${cropTypesField.value || 'Not set'}`;
                            }
                        }
                        if (livestockField) {
                            const livestockDisplay = Array.from(document.querySelectorAll('.profile-info-value')).find(el => el.textContent.includes('Not set') || el.textContent.includes('{{ profile.livestock_details }}'));
                            if (livestockDisplay) {
                                const icon = livestockDisplay.querySelector('i');
                                livestockDisplay.innerHTML = `<i class="fas fa-cow"></i> ${livestockField.value || 'Not set'}`;
                            }
                        }
                        
                        // Switch back to view mode
                        viewMode.style.display = 'block';
                        formWrap.style.display = 'none';
                        if (editBtnText) editBtnText.textContent = 'Edit Profile';
                    }
                }
                
                // Handle user (buyer) profile form toggle back to view mode
                if (form.id === 'profileForm') {
                    const viewMode = document.getElementById('buyerProfileViewMode');
                    const formWrap = document.getElementById('buyerProfileFormWrap');
                    const editBtnText = document.getElementById('editBtnText');
                    if (viewMode && formWrap) {
                        // Update profile display fields with form values
                        const nameField = form.querySelector('[name="name"]');
                        const emailField = form.querySelector('[name="email"]');
                        const contactField = form.querySelector('[name="contact"]');
                        const locationField = form.querySelector('[name="location"]');
                        
                        if (nameField) {
                            const nameDisplay = document.querySelector('[data-profile-name-display]');
                            if (nameDisplay) nameDisplay.textContent = nameField.value || 'Not set';
                        }
                        if (emailField) {
                            const emailDisplay = document.querySelector('[data-profile-email-display]');
                            if (emailDisplay) emailDisplay.textContent = emailField.value || 'Not set';
                        }
                        if (contactField) {
                            const contactDisplay = document.querySelector('[data-profile-contact-display]');
                            if (contactDisplay) {
                                const icon = contactDisplay.querySelector('i');
                                contactDisplay.innerHTML = `<i class="fas fa-phone"></i> ${contactField.value || 'Not set'}`;
                            }
                        }
                        if (locationField) {
                            const locationDisplay = document.querySelector('[data-profile-address-display]');
                            if (locationDisplay) {
                                const icon = locationDisplay.querySelector('i');
                                locationDisplay.innerHTML = `<i class="fas fa-map-marker-alt"></i> ${locationField.value || 'Not set'}`;
                            }
                        }
                        
                        // Switch back to view mode
                        viewMode.style.display = 'block';
                        formWrap.style.display = 'none';
                        if (editBtnText) editBtnText.textContent = 'Edit Profile';
                    }
                }
                
                // Handle vendor profile form toggle back to view mode
                if (form.id === 'vendorProfileForm') {
                    const viewMode = document.getElementById('vendorProfileViewMode');
                    const formWrap = document.getElementById('vendorProfileFormWrap');
                    const editBtnText = document.getElementById('vendorEditBtnText');
                    if (viewMode && formWrap) {
                        // Update profile display fields with form values
                        const emailField = form.querySelector('[name="email"]');
                        const companyField = form.querySelector('[name="company_name"]');
                        const contactField = form.querySelector('[name="contact"]');
                        const websiteField = form.querySelector('[name="website"]');
                        const businessTypeField = form.querySelector('[name="business_type"]');
                        const addressField = form.querySelector('[name="address"]');
                        
                        if (emailField) {
                            const emailDisplay = document.querySelector('[data-profile-email-display]');
                            if (emailDisplay) emailDisplay.textContent = emailField.value || 'Not set';
                        }
                        if (companyField) {
                            const companyDisplay = document.querySelector('[data-profile-company-display]');
                            if (companyDisplay) companyDisplay.textContent = companyField.value || 'Not set';
                        }
                        if (contactField) {
                            const contactDisplay = document.querySelector('[data-profile-contact-display]');
                            if (contactDisplay) {
                                const icon = contactDisplay.querySelector('i');
                                contactDisplay.innerHTML = `<i class="fas fa-phone"></i> ${contactField.value || 'Not set'}`;
                            }
                        }
                        if (websiteField) {
                            const websiteDisplay = document.querySelector('[data-profile-website-display]');
                            if (websiteDisplay) {
                                const icon = websiteDisplay.querySelector('i');
                                websiteDisplay.innerHTML = `<i class="fas fa-globe"></i> ${websiteField.value || 'Not set'}`;
                            }
                        }
                        if (businessTypeField) {
                            const businessTypeDisplay = document.querySelector('[data-profile-business-type-display]');
                            if (businessTypeDisplay) {
                                const icon = businessTypeDisplay.querySelector('i');
                                businessTypeDisplay.innerHTML = `<i class="fas fa-briefcase"></i> ${businessTypeField.value || 'Not set'}`;
                            }
                        }
                        if (addressField) {
                            const addressDisplay = document.querySelector('[data-profile-address-display]');
                            if (addressDisplay) {
                                const icon = addressDisplay.querySelector('i');
                                addressDisplay.innerHTML = `<i class="fas fa-map-marker-alt"></i> ${addressField.value || 'Not set'}`;
                            }
                        }
                        
                        // Switch back to view mode
                        viewMode.style.display = 'block';
                        formWrap.style.display = 'none';
                        if (editBtnText) editBtnText.textContent = 'Edit Profile';
                    }
                }
                if (data.tip_status && data.tip_status.id != null) {
                    const card = document.querySelector('[data-tip-row="' + data.tip_status.id + '"]');
                    if (card) {
                        const badge = card.querySelector('.status-badge');
                        if (badge && data.tip_status.approval_status) {
                            const st = data.tip_status.approval_status;
                            badge.className = 'status-badge ' + (st === 'approved' ? 'approved' : st === 'pending' ? 'pending' : 'rejected');
                            badge.textContent = st === 'approved' ? 'Approved' : st === 'pending' ? 'Pending approval' : 'Rejected';
                        }
                    }
                }
                const resetForm = form.getAttribute('data-farmity-reset-on-success') === '1';
                if (resetForm) form.reset();
                const closeModal = form.getAttribute('data-farmity-close-modal');
                if (closeModal) {
                    const m = document.getElementById(closeModal);
                    if (m) m.classList.remove('active');
                }

                // Optional post-success UI toggles / callbacks (for view-mode switching etc.)
                const hideSel = (form.getAttribute('data-farmity-success-hide') || '').trim();
                const showSel = (form.getAttribute('data-farmity-success-show') || '').trim();
                if (hideSel) {
                    hideSel.split(',').map(s => s.trim()).filter(Boolean).forEach(function (sel) {
                        document.querySelectorAll(sel).forEach(function (n) { n.style.display = 'none'; });
                    });
                }
                if (showSel) {
                    showSel.split(',').map(s => s.trim()).filter(Boolean).forEach(function (sel) {
                        document.querySelectorAll(sel).forEach(function (n) { n.style.display = ''; });
                    });
                }
                const callName = (form.getAttribute('data-farmity-success-call') || '').trim();
                if (callName && typeof window[callName] === 'function') {
                    try { window[callName](); } catch (e) {}
                }
            } else {
                if (typeof showError === 'function') {
                    showError(data.message || 'Something went wrong.');
                }
            }
        } catch (e) {
            if (typeof showError === 'function') {
                showError('Network error. Please try again.');
            }
        } finally {
            if (submitBtn) {
                submitBtn.disabled = false;
                submitBtn.innerHTML = prevText;
            }
        }
    }

    document.addEventListener('submit', function (ev) {
        const form = ev.target;
        if (!form || form.tagName !== 'FORM') return;
        if (form.getAttribute('data-farmity-ajax') !== '1') return;
        ev.preventDefault();
        submitFarmityForm(form);
    });
})();
