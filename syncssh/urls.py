"""
URL configuration for syncssh project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/6.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from django.http import HttpResponseRedirect
from django.conf import settings
from django.views.generic import RedirectView

from allauth.account.views import SignupView as AllauthSignupView


class InviteGatedSignupView(AllauthSignupView):
    """Allauth signup exists only for the invite-accept bounce.

    A signup through allauth never creates a workspace (only the API SignupView
    does), so a visitor without a pending invite would end up as an org-less
    account that 403s everywhere. Bounce them to the React signup instead.
    Gating dispatch (not just GET) also blocks scripted POSTs.
    """

    def dispatch(self, request, *args, **kwargs):
        if not request.session.get("invite_token"):
            return HttpResponseRedirect(settings.FRONTEND_BASE_URL + "/signup")
        return super().dispatch(request, *args, **kwargs)


urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/v1/", include("api.urls")),
    # Must precede the allauth include so it shadows allauth's own signup URL.
    path("accounts/signup/", InviteGatedSignupView.as_view(), name="account_signup"),
    # After a completed password reset, skip allauth's redundant done page and
    # land on the React login with a success notice. Relative URL on purpose —
    # same host the user reset on (see LOGIN_REDIRECT_URL). The name must match
    # allauth's, since its reset view reverses it as the success URL.
    path(
        "accounts/password/reset/key/done/",
        RedirectView.as_view(url="/login?reset=done"),
        name="account_reset_password_from_key_done",
    ),
    path("accounts/", include("allauth.urls")),
    path("", lambda _: HttpResponseRedirect(settings.FRONTEND_BASE_URL + "/")),
]
