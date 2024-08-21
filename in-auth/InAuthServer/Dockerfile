# 使用官方的 .NET SDK 映像檔作為基底
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build

# 設定工作目錄
WORKDIR /app

# 複製專案檔案到容器中
COPY . .
# 執行 restore 指令以還原相依套件
RUN dotnet restore

# 執行 build 指令以編譯應用程式
RUN dotnet build -c Release ./InAuthServer/InAuthServer.csproj

# 執行 publish 指令以發佈應用程式
RUN dotnet publish -c Release -o out

# 使用官方的 .NET 运行时映像檔作為基底
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS runtime

# 設定工作目錄
WORKDIR /app

EXPOSE 8080
# 複製 build 階段中發佈的檔案到容器中
COPY --from=build /app/out/ ./
ENTRYPOINT ["dotnet", "InAuthServer.dll"]
