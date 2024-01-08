from rest_framework import renderers
from rest_framework.exceptions import ErrorDetail

class CustomJSONRenderer(renderers.JSONRenderer):
    def render(self, data, accepted_media_type=None, renderer_context=None):
        result_data = data
        status_txt = 'success'
        message_txt = data["message"] if "message" in data else ""
        print(data)
        if isinstance(data, dict):
            if 'detail' in data and isinstance(data['detail'], ErrorDetail):
                status_txt = 'error'
                message_txt = str(data['detail'])
                result_data = {
                    'err_message': str(data['detail']),
                    'err_code': data['detail'].code
                }
            if 'non_field_errors' in data:
                status_txt = 'error'
                message_txt = 'Validation errors found, see `data` element'
                result_data = {
                    'err_messages': data['non_field_errors']
                }
        print(data)
        custom_data = {
            'status': status_txt,
            # 'message': message_txt,
            'response': {k: ', '.join(v) if isinstance(v, list) else v for k, v in result_data.items()} if isinstance(result_data,dict) is not None else ''
        }
        print(custom_data)
        return super(CustomJSONRenderer, self).render(
            data=custom_data,
            accepted_media_type=accepted_media_type,
            renderer_context=renderer_context)