# coding: utf-8
# 시스템 접근
import os
import sys
# 텐서플로우 디버깅 메시지 Off.
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
# 행렬 계산
import numpy as np
import pandas as pd
# 이미지 처리
import cv2
from PIL import Image
import matplotlib.pyplot as plt
# 모델 구현
import tensorflow as tf
from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing import image
from tensorflow.keras.preprocessing.image import ImageDataGenerator
from tensorflow.keras import Sequential
from tensorflow.keras.layers import InputLayer, Conv2D, MaxPool2D, Flatten, BatchNormalization, Dropout, Dense, LeakyReLU
from tensorflow.keras.optimizers import RMSprop, SGD
from tensorflow.keras.regularizers import l2
from sklearn.model_selection import cross_val_score, cross_validate
from sklearn.metrics import f1_score
from sklearn.metrics import roc_curve, auc
from tensorflow.keras.metrics import Accuracy, Precision, Recall, AUC
from tensorflow.keras.callbacks import ModelCheckpoint, EarlyStopping, CSVLogger

# PREPROCESSING
import shutil
import numpy as np
from sklearn.model_selection import train_test_split


TARGET_SIZE = (96, 96)
BATCH_SIZE = 64

class PREPROCESSING(object):
    
    def __init__(self):
        pass

    def _get_dataset_category(self, prefix):
        real, easy, mid, hard = [], [], [], []
        for (root, _, files) in os.walk(prefix):
            root = root + '/'
            for file in files:
                category = file.split('_')[0]
                path = root + file
                if category == "real":
                    real.append(path)
                if category == "easy":
                    easy.append(path)
                if category == "mid":
                    mid.append(path)
                if category == "hard":
                    hard.append(path)

        return real, easy, mid, hard


    def split_datset(self):
        real, easy, mid, hard = self._get_dataset_category('exclude/train/')

        real_train, real_test = train_test_split(real, test_size=0.4, shuffle=True, random_state=521)
        real_test, real_valid = train_test_split(real_test, test_size=0.5, shuffle=True, random_state=521)

        easy_train, easy_test = train_test_split(easy, test_size=0.4, shuffle=True, random_state=521)
        easy_test, easy_valid = train_test_split(easy_test, test_size=0.5, shuffle=True, random_state=521)

        mid_train, mid_test = train_test_split(mid, test_size=0.4, shuffle=True, random_state=521)
        mid_test, mid_valid = train_test_split(mid_test, test_size=0.5, shuffle=True, random_state=521)

        hard_train, hard_test = train_test_split(hard, test_size=0.4, shuffle=True, random_state=521)
        hard_test, hard_valid = train_test_split(hard_test, test_size=0.5, shuffle=True, random_state=521)

        
        print ('[*] Real Dataset')
        print ('- 학습용 : {}개'.format(len(real_train)))
        print ('- 검증용 : {}개'.format(len(real_valid)))
        print ('- 테스트 : {}개\n'.format(len(real_test)))

        print ('[*] Easy Dataset')
        print ('- 학습용 : {}개'.format(len(easy_train)))
        print ('- 검증용 : {}개'.format(len(easy_valid)))
        print ('- 테스트 : {}개\n'.format(len(easy_test)))

        print ('[*] Mid Dataset')
        print ('- 학습용 : {}개'.format(len(mid_train)))
        print ('- 검증용 : {}개'.format(len(mid_valid)))
        print ('- 테스트 : {}개\n'.format(len(mid_test)))

        print ('[*] Hard Dataset')
        print ('- 학습용 : {}개'.format(len(hard_train)))
        print ('- 검증용 : {}개'.format(len(hard_valid)))
        print ('- 테스트 : {}개\n'.format(len(hard_test)))

        return real_train, real_valid, real_test, easy_train, easy_valid, easy_test, \
            mid_train, mid_valid, mid_test, hard_train, hard_valid, hard_test


    def create_dataset_folder(self):
        if not os.path.exists('exclude/dataset'):
            os.mkdir('exclude/dataset')

        if not os.path.exists('exclude/dataset/train'):
            os.mkdir('exclude/dataset/train')

        if not os.path.exists('exclude/dataset/test'):
            os.mkdir('exclude/dataset/test')

        if not os.path.exists('exclude/dataset/train/real'):
            os.mkdir('exclude/dataset/train/real')

        if not os.path.exists('exclude/dataset/train/fake'):
            os.mkdir('exclude/dataset/train/fake')

        if not os.path.exists('exclude/dataset/test/real'):
            os.mkdir('exclude/dataset/test/real')

        if not os.path.exists('exclude/dataset/test/fake'):
            os.mkdir('exclude/dataset/test/fake')


    def copy_dataset(self, dataset):
        for i in range(len(dataset)):
            for j in range(len(dataset[i])):
                if i == 0 or i == 1:
                    shutil.copy2(dataset[i][j], 'exclude/dataset/train/real/' + dataset[i][j].split('/')[-1])
                if i == 2:
                    shutil.copy2(dataset[i][j], 'exclude/dataset/test/real/' + dataset[i][j].split('/')[-1])
                if i == 4 or i == 5 or i == 7 or i == 8 or i == 10 or i==11:
                    shutil.copy2(dataset[i][j], 'exclude/dataset/test/fake/' + dataset[i][j].split('/')[-1])
                if i == 3 or i == 6 or i == 9:
                    shutil.copy2(dataset[i][j], 'exclude/dataset/train/fake/' + dataset[i][j].split('/')[-1])
        
        print ('[*] Finished copying dataset\n')


class SynDetectModel(object):
    def __init__(self):
        self.model = tf.keras.Sequential(self._build_layer())
        #self.model.compile(optimizer=RMSprop(learning_rate=1e-5), loss='binary_crossentropy', metrics=['accuracy', Precision(name='precision'), Recall(name='recall'), AUC(name='auc')])
        self.model.compile(optimizer=RMSprop(learning_rate=1e-5), loss='binary_crossentropy', metrics=['accuracy'])
        # self.model.compile(optimizer=SGD(learning_rate=0.0001), loss='categorical_crossentropy', metrics=['accuracy', Precision(name='precision'), Recall(name='recall'), AUC(name='auc')])
        self.model.summary()
        self.model_checkpoint = ModelCheckpoint('exclude/syn_best_model.h5', monitor='loss', mode='min', save_best_only=True)
        self.csv_logger = CSVLogger('exclude/syn_training.log')


    def augment_image(self):
        train_path = 'exclude/dataset/train/'
        test_path = 'exclude/dataset/test/'

        train_generator = ImageDataGenerator(horizontal_flip=True, vertical_flip=False, shear_range=0.3, zoom_range=0.3, rescale=1 / 255)
        # train_generator = ImageDataGenerator(horizontal_flip=False, vertical_flip=False, rescale=1 / 255)
        test_generator = ImageDataGenerator(rescale=1 / 255, validation_split=0.5)

        train_set = train_generator.flow_from_directory(train_path, batch_size=BATCH_SIZE, class_mode='binary', target_size=TARGET_SIZE, color_mode='rgb', shuffle=False)
        valid_set = test_generator.flow_from_directory(test_path, batch_size=BATCH_SIZE, class_mode='binary', target_size=TARGET_SIZE, color_mode='rgb', subset='training')
        test_set = test_generator.flow_from_directory(test_path, batch_size=BATCH_SIZE, class_mode='binary', target_size=TARGET_SIZE, color_mode='rgb', subset='validation')

        return train_set, valid_set, test_set


    def _build_layer(self):
        layers = [
            #Conv2D(32, (3, 3), padding='same', input_shape=(TARGET_SIZE[0], TARGET_SIZE[1], 3), activation=LeakyReLU(0.1)),
            Conv2D(32, (3, 3), padding='same', input_shape=(TARGET_SIZE[0], TARGET_SIZE[1], 3), activation='relu'),
            #Conv2D(32, (3, 3), padding='same', activation=LeakyReLU(0.1)),
            MaxPool2D(pool_size=(2, 2)),
            BatchNormalization(),
            Dropout(0.5),

            Conv2D(32, (3, 3), padding='same', activation='relu'),
            #Conv2D(64, (3, 3), padding='same', activation=LeakyReLU(0.1)),
            MaxPool2D(pool_size=(2, 2)),
            BatchNormalization(),
            Dropout(0.5),

            Conv2D(64, (3, 3), padding='same', activation='relu'),
            #Conv2D(64, (3, 3), padding='same', activation=LeakyReLU(0.1)),
            MaxPool2D(pool_size=(2, 2)),
            BatchNormalization(),
            Dropout(0.5),

            # Conv2D(256, (3, 3), padding='same', activation=LeakyReLU(0.1)),
            # MaxPool2D(pool_size=(2, 2)),
            # BatchNormalization(),

            Flatten(),
            Dense(units=64, activation='relu'),
            # Dense(units=64, activation=LeakyReLU(0.1)),
            Dropout(0.5),
            Dense(units=2),
            Dense(units=1, activation='sigmoid')]

        return layers

    def loss(self, y_true, y_pred):
        pass

    def accuracy(self, y_true, y_pred):
        pass

    def is_model_saved(self):
        try:
            self.model = load_model('exclude/syn_detect_model.h5')
            return True

        except Exception as ex:
            return False


    def fit(self, train_set, valid_set, n_epochs, early_stop):
        print ('[*] Start fitting the model')
        try:
            self.model = load_model('exclude/syn_detect_model.h5')
            print ('[*] Skip fitting the model')
            return None
        except:
            history = self.model.fit(train_set, validation_data=valid_set, epochs=n_epochs, callbacks=[early_stop, self.model_checkpoint, self.csv_logger], verbose=1)
            self.model.save('exclude/syn_detect_model.h5')
            return history


    def evaluate(self, valid_set):
        print ('[*] Start evaluating the model')
        return self.model.evaluate(valid_set, verbose=1)


    def predict(self, test_set):
        print ('[*] Start prediction')
        return self.model.predict(test_set, verbose=1)


    def test_predict(self):
        print ('[*] Start inference')

        y_pred = list()
        fake_images = os.listdir('exclude/dataset/test/fake/')
        real_images = os.listdir('exclude/dataset/test/real/')

        fullpath = []
        for (root, dirs, files) in os.walk('exclude/dataset/test/'):
            
            root = root + '/'
            for file in files:
                path = root + file
                fullpath.append(path)

        for i in range(len(fullpath)):
            # print (fullpath[i])
            test_image = image.load_img(fullpath[i], target_size=(TARGET_SIZE[0], TARGET_SIZE[1], 3))
            test_image = image.img_to_array(test_image)
            test_image = np.expand_dims(test_image, axis=0) / 255.
            predict_result = self.model.predict_classes(test_image)
            #predict_result2 = np.argmax(self.model.predict(test_image), axis=-1)
            if predict_result[0][0] == 0:
                print("[*] Fake : {}".format(fullpath[i].split('/')[-1]))
                y_pred.append(predict_result[0][0])

            elif predict_result[0][0] == 1:
                print("[*] Real : {}".format(fullpath[i].split('/')[-1]))
                y_pred.append(predict_result[0][0])

        y_true_fake = [0 for i in range(len(fake_images))]
        y_true_real = [1 for i in range(len(real_images))]
        y_true = y_true_fake + y_true_real
        print (f"[*] F1 Score: {f1_score(y_true, y_pred, average='micro')}")


    def cross_validation(self, train_set):
        return cross_val_score(self.model, train_set, cv=3)


class LocDetectModel(object):
    def __init__(self):
        self.model = tf.keras.Sequential(self._build_layer())
        #self.model.compile(optimizer=RMSprop(learning_rate=1e-5), loss='categorical_crossentropy', metrics=['accuracy', Precision(name='precision'), Recall(name='recall'), AUC(name='auc')])
        self.model.compile(optimizer=SGD(learning_rate=0.001, clipnorm=1.), loss='categorical_crossentropy', metrics=['accuracy', Precision(name='precision'), Recall(name='recall'), AUC(name='auc')])
        self.model.summary()
        self.model_checkpoint = ModelCheckpoint('exclude/loc_best_model.h5', monitor='loss', mode='min', save_best_only=True)
        self.csv_logger = CSVLogger('exclude/loc_training.log')


    def create_df(self):
        train_path = 'exclude/dataset/train/'
        test_path = 'exclude/dataset/test/'

        # Train dataframe
        train_frames = list()
        fake_fnames = os.listdir(train_path + 'fake/')
        for i in range(len(fake_fnames)):
            train_frame = list()
            fake_fname_label = fake_fnames[i].split('.')[0].split('_')[-1] # ex) 1010, 0011, 1111, 0111 ...
            train_frame.append(fake_fnames[i])
            train_frame.append(fake_fname_label[0])
            train_frame.append(fake_fname_label[1])
            train_frame.append(fake_fname_label[2])
            train_frame.append(fake_fname_label[3])
            train_frames.append(train_frame)


        # Test dataframe
        test_frames = list()
        fake_fnames = os.listdir(test_path + 'fake/')
        for i in range(len(fake_fnames)):
            test_frame = list()
            fake_fname_label = fake_fnames[i].split('.')[0].split('_')[-1]
            test_frame.append(fake_fnames[i])
            test_frame.append(fake_fname_label[0])
            test_frame.append(fake_fname_label[1])
            test_frame.append(fake_fname_label[2])
            test_frame.append(fake_fname_label[3])
            test_frames.append(test_frame)

        train_df = pd.DataFrame(train_frames, columns=['filename', 'left_eye', 'right_eye', 'nose', 'mouth'])
        test_df = pd.DataFrame(test_frames, columns=['filename', 'left_eye', 'right_eye', 'nose', 'mouth'])

        train_df['label'] = train_df['left_eye'] + train_df['right_eye'] + train_df['nose'] + train_df['mouth']
        test_df['label'] = test_df['left_eye'] + test_df['right_eye'] + test_df['nose'] + test_df['mouth']

        return train_df, test_df


    def augment_image(self, train_df, test_df):
        train_gen = ImageDataGenerator(# featurewise_center = True, featurewise_std_normalization = True,
            # width_shift_range=0.2, height_shift_range=0.2, # rescale = 1./255., rotation_range = 15,
            # vertical_flip = False, fill_mode='nearest'
            #shear_range=0.2, zoom_range=0.2)
        )

        test_gen = ImageDataGenerator(validation_split=0.5)

        train_set = train_gen.flow_from_dataframe(dataframe=train_df,
                                                  directory="exclude/dataset/train/fake/", x_cols="filename",
                                                  y_col="label",
                                                  class_mode="categorical",
                                                  target_size=TARGET_SIZE,
                                                  batch_size=BATCH_SIZE,
                                                  save_to_dir='exclude/preview',
                                                  save_format='jpeg')

        valid_set = test_gen.flow_from_dataframe(dataframe=test_df,
                                                 directory="exclude/dataset/test/fake/", x_cols="filename",
                                                 y_col="label",
                                                 class_mode="categorical",
                                                 target_size=TARGET_SIZE,
                                                 batch_size=BATCH_SIZE,
                                                 subset='training',
                                                 save_to_dir='exclude/preview',
                                                 save_format='jpeg')

        test_set = test_gen.flow_from_dataframe(dataframe=test_df,
                                                class_mode="categorical",
                                                directory="exclude/dataset/test/fake/", x_cols="filename",
                                                y_col="label",
                                                subset="validation",
                                                batch_size=1)
        #print(test_set.class_indices)  # 라벨 확인
        return train_set, valid_set, test_set


    def _build_layer(self):

        layers = [
            Conv2D(32, (3, 3), padding='same', input_shape=(TARGET_SIZE[0], TARGET_SIZE[1], 3), activation=LeakyReLU(0.1)),
            Conv2D(32, (3, 3), padding='same', activation=LeakyReLU(0.1)),
            MaxPool2D(pool_size=(2, 2)),

            Conv2D(64, (3, 3), padding='same', activation=LeakyReLU(0.1)),
            Conv2D(64, (3, 3), padding='same', activation=LeakyReLU(0.1)),
            MaxPool2D(pool_size=(2, 2)),
            BatchNormalization(),
            #Dropout(0.2),

            Conv2D(128, (3, 3), padding='same', activation=LeakyReLU(0.1)),
            MaxPool2D(pool_size=(2, 2)),
            BatchNormalization(),
            #Dropout(0.2),

            Conv2D(256, (3, 3), padding='same', activation=LeakyReLU(0.1)),
            MaxPool2D(pool_size=(2, 2)),
            BatchNormalization(),

            Flatten(),
            Dense(units=128, activation=LeakyReLU(0.1)),
            Dense(units=15, activation='softmax')]

        return layers


    def accuracy(self):
        pass

    def loss(self):
        pass


    def fit(self, train_set, valid_set, n_epochs, early_stop):
        print('[*] Start fitting the model')
        try:
            self.model = load_model('exclude/loc_detect_model.h5')
            return None
        except:
            history = self.model.fit(train_set, validation_data=valid_set, epochs=n_epochs, callbacks=[early_stop, self.model_checkpoint, self.csv_logger], verbose=1)
            self.model.save('exclude/loc_detect_model.h5')
            return history


    def evaluate(self, valid_set):
        print('[*] Start evaluating the model')
        return self.model.evaluate(valid_set, verbose=1)


    def predict(self, test_set):
        print ('[*] Start prediction')
        return self.model.predict(test_set, verbose=1)


    def test_predict(self, test_set):
        print('[*] Start inference')
        print(test_set.class_indices)
        map_table = {0: '0001', 1: '0010', 2: '0011', 3: '0100', 4: '0101', 5: '0110', 6: '0111', 7: '1000',
                     8: '1001', 9: '1010', 10: '1011', 11: '1100', 12: '1101', 13:'1110', 14:'1111'}

        y_pred = list()
        y_true = list()
        fake_images = os.listdir('exclude/dataset/test/fake/')
        for i in fake_images:
            img = image.load_img('exclude/dataset/test/fake/' + i, target_size=(TARGET_SIZE[0], TARGET_SIZE[1], 3))
            img = image.img_to_array(img)
            img = img.reshape(-1, TARGET_SIZE[0], TARGET_SIZE[1], 3)

            predict_result = self.model.predict_classes(img, verbose=0)

            fname = i.split('.')[0].split('_')[-1]
            real_label = test_set.class_indices[fname]

            y_true.append(real_label)
            y_pred.append(predict_result[0])

            r_result = map_table[real_label]
            p_result = map_table[predict_result[0]]

            left_eye, right_eye, nose, mouth = False, False, False, False

            if r_result == p_result:
                if p_result[0] == "1":
                    left_eye = True
                if p_result[1] == "1":
                    right_eye = True
                if p_result[2] == "1":
                    nose = True
                if p_result[3] == "1":
                    mouth = True
                print(f"[*] {i} : {real_label}, {predict_result[0]}\n  [+] 왼 : {left_eye}, \n  [+] 오 : {right_eye}\n  [+] 코 : {nose}\n  [+] 입 : {mouth}")

            else:
                print(f"[!] {i} : {real_label}, {predict_result[0]} --> Fail")

        print(f"[*] F1 Score: {round(f1_score(y_true, y_pred, average='micro'),4)}")





def plot(epochs, history, prefix):
    xc = range(epochs)
    train_loss = history.history['loss']
    val_loss = history.history['val_loss']
    train_acc = history.history['accuracy']
    val_acc = history.history['val_accuracy']

    plt.figure(1, figsize=(7, 5))
    plt.plot(xc, train_loss)
    plt.plot(xc, val_loss)
    plt.xlabel('Num of Epochs')
    plt.ylabel('Loss')
    plt.title('Train loss vs Validation loss')
    plt.grid(True)
    plt.legend(['Train', 'Validation'], loc=4)
    plt.style.use(['classic']) # print plt.style.available # use bmh, classic,ggplot for big pictures
    plt.savefig('exclude/{}_loss.png'.format(prefix))

    plt.figure(2, figsize=(7, 5))
    plt.plot(xc, train_acc)
    plt.plot(xc, val_acc)
    plt.xlabel('Num of Epochs')
    plt.ylabel('Accuracy')
    plt.title('Train accuracy vs Validation accuracy')
    plt.grid(True)
    plt.legend(['Train', 'Validation'], loc=4)
    plt.style.use(['classic'])
    plt.savefig('exclude/{}_accuracy.png'.format(prefix))
    plt.cla()


def main():

    # Preprocessing
    # PRE = PREPROCESSING()
    # dataset = PRE.split_datset()
    # PRE.create_dataset_folder()
    # PRE.copy_dataset(dataset)


    # Training/Inference
    S = SynDetectModel()
    L = LocDetectModel()


    epochs = 2000
    early_stop = EarlyStopping(monitor='loss', patience=10)

    # Synthesis Detection --> True/False
    train_set, valid_set, test_set = S.augment_image()
    history = S.fit(train_set, valid_set, epochs, early_stop)
    if history is not None:
        plot(early_stop.stopped_epoch + 1, history, "syn")
    evaluation = S.evaluate(valid_set)
    print(f'\n[+] Loss : {round(evaluation[0],4)}\n[+] Accuracy : {round(evaluation[1], 4)}\n[+] Precision : {round(evaluation[2], 4)}\n[+] Recall : {round(evaluation[3], 4)}\n[+] AUC : {round(evaluation[4], 4)}\n')
    #predict = S.predict(test_set)
    S.test_predict()
    #S.cross_validation(train_set)


    # # Location Detection --> Left eye, Right eye, Nose, Mouth
    # train_df, test_df = L.create_df()
    # train_set, valid_set, test_set = L.augment_image(train_df, test_df)
    # history2 = L.fit(train_set, valid_set, epochs, early_stop)
    # if history is not None:
    #     plot(early_stop.stopped_epoch + 1, history2, "loc")
    # evaluation2 = L.evaluate(valid_set)
    # print(f'\n[+] Loss : {round(evaluation2[0],4)}\n[+] Accuracy : {round(evaluation2[1], 4)}\n[+] Precision : {round(evaluation2[2], 4)}\n[+] Recall : {round(evaluation2[3], 4)}\n[+] AUC : {round(evaluation2[4], 4)}\n')
    # #predict2 = L.predict(test_set)
    # L.test_predict(test_set)


if __name__ == "__main__":
    main()