FROM eclipse-temurin:21-jre
WORKDIR /haxall
COPY haxall-dist/ /haxall/
RUN chmod +x /haxall/bin/*
