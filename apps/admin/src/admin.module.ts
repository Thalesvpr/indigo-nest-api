import { Module } from '@nestjs/common';
import { AdminController } from './admin.controller';
import { AdminService } from './admin.service';
import { AuthModule } from './auth/auth.module'; // Importa o AuthModule
import { ConfigModule } from '@nestjs/config';
import { PrismaModule } from 'apps/admin/src/prisma/prisma.module'; // Verifique o caminho correto
import { APP_GUARD } from '@nestjs/core';
import { PublicRoutesGuard } from './auth/public-routes.guard';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
    }),
    PrismaModule,
    AuthModule,
  ],
  controllers: [AdminController],
  providers: [
    AdminService,
    {
      provide: APP_GUARD,
      useClass: PublicRoutesGuard,
    },
  ],
})
export class AdminModule {}
