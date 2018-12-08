FROM python:3.7-alpine3.7

ARG project_dir=/app/

#ADD main.py $project_dir
WORKDIR $project_dir

RUN pip install flask redis

CMD ["python", "main.py"]

