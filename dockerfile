FROM python:slim-buster	

WORKDIR /alitoken
COPY . /alitoken
RUN pip install -i https://pypi.mirrors.ustc.edu.cn/simple/ -r /alitoken/requirements.txt \
    && cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime && echo 'Asia/Shanghai' >/etc/timezone
CMD ["python", "main.py"]