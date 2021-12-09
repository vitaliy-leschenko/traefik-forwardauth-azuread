FROM mcr.microsoft.com/dotnet/aspnet:6.0 AS base
WORKDIR /app
EXPOSE 80

FROM mcr.microsoft.com/dotnet/sdk:6.0 AS build
WORKDIR /src
COPY ["TraefikAuthAAD/TraefikAuthAAD.csproj", "TraefikAuthAAD/"]
RUN dotnet restore "TraefikAuthAAD/TraefikAuthAAD.csproj"
COPY . .
WORKDIR "/src/TraefikAuthAAD"
RUN dotnet build "TraefikAuthAAD.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "TraefikAuthAAD.csproj" -c Release -o /app/publish

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "TraefikAuthAAD.dll"]