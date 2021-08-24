from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin
import aiohttp
import asyncio


class forms:

    policy = asyncio.WindowsSelectorEventLoopPolicy()
    asyncio.set_event_loop_policy(policy)

    @classmethod
    async def get_forms(self, url, async_session):
        returned_forms = []
        # This function is standing for enumerating the forms existed on the given URL
        try:
            async with async_session.get(url) as resp:
                text = await resp.read()
                content = bs(text.decode('utf-8'), "html.parser")
        except (aiohttp.InvalidURL, UnicodeDecodeError):
            content = None
            pass

        if content is not None:
            form_Content = content.find_all("form")

            for form in form_Content:
                form_specs = {}
                action = form.attrs.get("action").lower()
                method = form.attrs.get("method", "get").lower()
                inputs = []
                for input_tag in form.find_all("input"):
                    input_type = input_tag.attrs.get("type", "text")
                    if hasattr(input_tag, "value"):
                        input_value = input_tag.attrs.get("value")
                    else:
                        input_value = ""
                    input_name = input_tag.attrs.get("name")
                    inputs.append({"type": input_type, "name": input_name, "value": input_value})

                form_specs["url"] = url
                form_specs["action"] = action
                form_specs["method"] = method
                form_specs["inputs"] = inputs
                returned_forms.append(form_specs)
        return returned_forms

    @classmethod
    async def async_get_forms(cls, crawler, cookies):
        async with aiohttp.ClientSession(cookies=cookies) as s:
            tasks = []
            for url in crawler:
                task = asyncio.ensure_future(forms.get_forms(url=url, async_session=s))
                tasks.append(task)
            response = await asyncio.gather(*tasks)
        return response

    @classmethod
    async def submit(cls, url, form_specs, async_session, payload):
        data = {}
        target_url = urljoin(url, form_specs["action"])
        inputs = form_specs["inputs"]
        formlist = []

        for input in inputs:
            if input["type"] == "text" or input["type"] == "search" \
                    or input["type"].lower() == "textarea":
                input["value"] = payload
                input_name = input["name"]
                input_value = input["value"]

                if input_name and input_value:
                    data[input_name] = input_value

            else:
                value = input["name"]
                name = input["value"]
                data[name] = value

            try:
                async with async_session.post(data=data, url=target_url) as response:
                    text = await response.text()
                    formlist.append({"url": target_url, "content": text})
            except aiohttp.ClientConnectionError:
                pass
        return formlist

    @classmethod
    async def async_submit(cls, formlist, payloads, cookies=None):
        tasks = []
        async with aiohttp.ClientSession(cookies=cookies, trust_env=True) as S:
            for each_page in formlist:
                for each_form in each_page:
                    link = each_form['url']
                    form_specs = each_form
                    for each_payload in payloads:
                        task = asyncio.ensure_future(cls.submit(url=link, form_specs=form_specs, async_session=S, payload=each_payload))
                        tasks.append(task)
            response = await asyncio.gather(*tasks)
        return response

