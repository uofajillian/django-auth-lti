from django.contrib import auth

from django.core.exceptions import ImproperlyConfigured
from django.conf import settings
from ims_lti_py.tool_provider import DjangoToolProvider
from django.core.exceptions import PermissionDenied


from timer import Timer

import logging
logger = logging.getLogger(__name__)


class LTIAuthMiddleware(object):
    """
    Middleware for authenticating users via an LTI launch URL.

    If the request is an LTI launch request, then this middleware attempts to
    authenticate the username and signature passed in the POST data.
    If authentication is successful, the user is automatically logged in to
    persist the user in the session.

    If the request is not an LTI launch request, do nothing.
    """

    def __init__(self):
        # get credentials from config
        self.oauth_creds = settings.LTI_OAUTH_CREDENTIALS

    def process_request(self, request):
        logger.debug('inside process_request %s' % request.path)
        # AuthenticationMiddleware is required so that request.user exists.
        if not hasattr(request, 'user'):
            logger.debug('improperly configured: requeset has no user attr')
            raise ImproperlyConfigured(
                "The Django LTI auth middleware requires the"
                " authentication middleware to be installed.  Edit your"
                " MIDDLEWARE_CLASSES setting to insert"
                " 'django.contrib.auth.middleware.AuthenticationMiddleware'"
                " before the PINAuthMiddleware class.")
        if request.method == 'POST' and request.POST.get('lti_message_type') == 'basic-lti-launch-request':

            logger.debug('received a basic-lti-launch-request - authenticating the user')
            logger.debug("testing, testing!")
            request_key = request.POST.get('oauth_consumer_key', None)
            if request_key is None:
                logger.error("Request doesn't contain an oauth_consumer_key; can't continue.")
                return None
            logger.debug("request key is %s" % request_key)

            secret = self.oauth_creds.get(request_key, None)

            if not secret:
                logger.error("Could not get a secret for key %s" % request_key)

            logger.debug('using key/secret %s/%s' % (request_key, secret))
            tool_provider = DjangoToolProvider(request_key, secret, request.POST.dict())

            # authenticate and log the user in
            with Timer() as t:
                user = auth.authenticate(request=request, tool_provider=tool_provider)
            logger.debug('authenticate() took %s s' % t.secs)

            if user is not None:
                # User is valid.  Set request.user and persist user in the session
                # by logging the user in.

                logger.debug('user was successfully authenticated; now log them in')
                request.user = user
                with Timer() as t:
                    auth.login(request, user)
    
                logger.debug('login() took %s s' % t.secs)

                lti_launch = tool_provider.to_params()
                # Fix for bug in ims_lti.py port where lis_course_offering_sourcedid is not passed
                lti_launch['lis_course_offering_sourcedid'] = request.POST.get('lis_course_offering_sourcedid', '')
                # If a custom role key is defined in project, merge into existing role list
                if hasattr(settings, 'LTI_CUSTOM_ROLE_KEY'):
                    lti_launch['roles'] += tool_provider.get_custom_param(settings.LTI_CUSTOM_ROLE_KEY).split(',')
                
                request.lti_params = lti_launch
            else:
                # User could not be authenticated!
                logger.warning('user could not be authenticated via LTI params; let the request continue in case another auth plugin is configured')
 
    def clean_username(self, username, request):
        """
        Allows the backend to clean the username, if the backend defines a
        clean_username method.
        """
        backend_str = request.session[auth.BACKEND_SESSION_KEY]
        backend = auth.load_backend(backend_str)
        try:
            logger.debug('calling the backend %s clean_username with %s' % (backend, username))
            username = backend.clean_username(username)
            logger.debug('cleaned username is %s' % username)
        except AttributeError:  # Backend has no clean_username method.
            pass
        return username


class LTIContextMiddleware(object):

    def process_request(self, request):
        logger.debug("inside LTIContextMiddleware process_request!")
        if not hasattr(request, 'lti_params') and 'LTI_LAUNCH' in request.session:
            logger.debug("setting lti_params from session!")
            request.lti_params = request.session['LTI_LAUNCH']

    def process_response(self, request, response):
        if hasattr(request, 'lti_params'):
            logger.debug("storing lti_params in session!")
            request.session['LTI_LAUNCH'] = request.lti_params
        return response


class LTIMultipleContextMiddleware(object):

    def __init__(self):
        self.context_key = settings.LTI_CONTEXT_KEY

    def process_view(self, request, view_func, view_args, view_kwargs):
        logger.debug("inside multiple context process_view!")
        logger.debug("view_kwargs contains %s" % view_kwargs)
        if self.context_key in view_kwargs:
            context = view_kwargs[self.context_key]
        else:
            # If not part of url string then check if query parameter
            context = request.GET.get(self.context_key, None)

        if context:
            # Match up context key in session with key in url
            if context in request.session.get('LTI_LAUNCH', {}):
                logger.debug("setting launch params based on context of %s" % context)
                request.lti_params = request.session['LTI_LAUNCH'].get(context)
            else:  # Looks like someone's working in another context
                logger.error("User context %s for key %s not present in session" % (context, self.context_key))
                raise PermissionDenied("Bogus context specified!")

    def process_response(self, request, response):
        if hasattr(request, 'lti_params'):
            logger.debug("storing lti_params in session based on context!")
            self.add_launch_params_to_session(request.lti_params, request.session)
        return response

    def add_launch_params_to_session(self, params, session):
        # Determine key value based on context
        context = params.get(self.context_key)
        context_dict = session.get('LTI_LAUNCH', {})
        context_dict[context] = params
        session['LTI_LAUNCH'] = context_dict
        return params
